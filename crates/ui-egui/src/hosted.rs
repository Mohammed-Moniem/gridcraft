//! Host-authoritative workbook lifecycle over actual SheetApp/Session ownership.
use crate::SheetApp;
use gridcraft_engine::{
    core::{CellRef, RangeRef},
    model::Workbook,
};
use serde_json::{Value, json};
use std::cell::Cell;
use std::collections::BTreeSet;
use std::rc::Rc;
use std::sync::{Arc, atomic::Ordering};

/// Copy exports use the same acknowledged writer without adopting their bytes as the source.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SaveDisposition {
    Source,
    Copy,
}
pub type HostSaveFn = Box<dyn Fn(&str, &[u8], bool, u64, u64, Arc<Workbook>, SaveDisposition) -> Result<u64, String>>;
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum SaveOutcome {
    Saved,
    Failed,
}
#[derive(Default)]
struct QueueState {
    next: u64,
    pending: BTreeSet<u64>,
    finished: Vec<(u64, SaveOutcome)>,
}
#[derive(Clone, Default)]
pub struct SaveQueue(Rc<Cell<QueueState>>);
impl SaveQueue {
    fn with<T>(&self, f: impl FnOnce(&mut QueueState) -> T) -> T {
        let mut s = self.0.take();
        let out = f(&mut s);
        self.0.set(s);
        out
    }
    pub fn start(&self) -> Result<u64, String> {
        self.with(|s| {
            if s.pending.len() + s.finished.len() >= 8 || s.next >= 10000 {
                return Err("host save capacity reached".into());
            }
            s.next += 1;
            s.pending.insert(s.next);
            Ok(s.next)
        })
    }
    pub fn finish(&self, ticket: u64, outcome: SaveOutcome) {
        self.with(|s| {
            if s.pending.remove(&ticket) {
                s.finished.push((ticket, outcome));
            }
        });
    }
    fn take_finished(&self) -> Vec<(u64, SaveOutcome)> {
        self.with(|s| std::mem::take(&mut s.finished))
    }
}
/// View changes may replace the workbook without an undoable revision. Include the actual
/// immutable workbook identity so sheet activation is visible, but never count dirty storage.
#[derive(Default)]
pub struct RevisionClock {
    current: Option<(u64, u64, Arc<Workbook>, usize)>,
    revision: u64,
}
impl RevisionClock {
    pub fn sync(&mut self, document: u64, engine_revision: u64, workbook: Option<Arc<Workbook>>) -> u64 {
        let changed = match (&self.current, &workbook) {
            (Some((id, rev, old, sheet)), Some(wb)) => {
                *id != document || *rev != engine_revision || !Arc::ptr_eq(old, wb) || *sheet != wb.active_sheet()
            }
            (None, None) => false,
            _ => true,
        };
        if changed {
            self.revision = match &self.current {
                Some((id, rev, _, _)) if *id == document && engine_revision > *rev => self.revision.saturating_add(engine_revision - *rev),
                _ => self.revision.saturating_add(1),
            };
            self.current = workbook.map(|wb| {
                let sheet = wb.active_sheet();
                (document, engine_revision, wb, sheet)
            });
        }
        self.revision
    }
}
pub(crate) struct PendingSave {
    pub document: u64,
    ticket: u64,
    revision: u64,
    workbook: Arc<Workbook>,
    active_sheet: usize,
    bytes: usize,
    name: String,
    close: Option<(bool, egui::Context)>,
    disposition: SaveDisposition,
}

impl SheetApp {
    pub fn host_has_unsaved_documents(&self) -> bool {
        self.session.documents().iter().any(|d| d.is_dirty())
            || self.host_has_drafts()
            || !self.pending_host_saves.is_empty()
            || !self.host_unsaved.is_empty()
    }
    pub fn host_pending_saves(&self) -> usize {
        self.pending_host_saves.len()
    }
    pub fn host_update_dirty(&self) {
        self.host_dirty_flag.store(self.host_has_unsaved_documents(), Ordering::Relaxed);
    }
    pub fn host_document_identity(&self) -> Option<(u64, u64, Arc<Workbook>)> {
        self.session.active().map(|doc| (doc.uid, doc.revision, doc.wb.clone()))
    }
    pub fn open_from_host(&mut self, name: &str, bytes: Vec<u8>) -> Result<u64, String> {
        if self.host_has_unsaved_documents() || self.host_interaction_busy() {
            return Err("save or close unsaved owners and finish pending writes before opening".into());
        }
        if bytes.len() > 32 << 20 {
            return Err("host file exceeds 32 MiB".into());
        }
        let result = self.run("file.open", json!({"name":name,"base64":gridcraft_engine::io::base64_encode(&bytes)}))?;
        self.after_open(None, &result);
        self.session.active().map(|d| d.uid).ok_or("open did not activate a workbook".into())
    }
    pub fn close_from_host(&mut self, discard: bool) -> Result<(), String> {
        if !self.pending_host_saves.is_empty() || self.host_has_drafts() || self.host_interaction_busy() {
            return Err("resolve owned drafts/dialogs and pending writes before closing".into());
        }
        let uid = self.session.active().map(|doc| doc.uid);
        if self.session.documents().iter().any(|doc| Some(doc.uid) != uid && (doc.is_dirty() || self.host_unsaved.contains(&doc.uid))) {
            return Err("another workbook contains owned unsaved work".into());
        }
        if self.host_has_unsaved_documents() && !discard {
            return Err("save or explicitly discard the active workbook".into());
        }
        self.run("file.close", json!({"force":discard,"document":true}))?;
        if let Some(uid) = uid {
            self.host_unsaved.remove(&uid);
        }
        self.host_update_dirty();
        Ok(())
    }
    pub fn host_start_save(&mut self, save_as: bool) -> Result<Value, String> {
        if self.pending_host_saves.len() + self.finished_host_saves.len() >= 8 {
            return Err("too many pending host saves".into());
        }
        self.store_view_state();
        let doc = self.session.active().ok_or("no workbook is open")?;
        let (uid, revision, workbook) = (doc.uid, doc.revision, doc.wb.clone());
        let stem = std::path::Path::new(&doc.title).file_stem().and_then(|name| name.to_str()).unwrap_or("Book");
        // A normal Save must not silently strip carried-through VBA bytes and then mark the
        // workbook clean. Macro-enabled packages are preserved; GridCraft never runs that VBA.
        let extension = if workbook.vba_project.is_some() { "xlsm" } else { "xlsx" };
        let name = format!("{stem}.{extension}");
        let bytes = gridcraft_engine::io::save_bytes(&workbook, &name).map_err(|error| error.to_string())?;
        self.host_enqueue_write(name, bytes, save_as, (uid, revision, workbook), SaveDisposition::Source)
    }
    /// Copy exports never become the workbook's saved baseline or change its title/path.
    pub fn host_export_copy(&mut self, format: &str, name: Option<&str>) -> Result<Value, String> {
        if !["xlsx", "csv", "tsv", "json", "html"].contains(&format) {
            return Err("unsupported copy format".into());
        }
        self.settle_drafts()?;
        self.store_view_state();
        let doc = self.session.active().ok_or("no workbook is open")?;
        let hint = name.filter(|name| !name.trim().is_empty()).unwrap_or(&doc.title);
        let file = std::path::Path::new(hint).file_name().and_then(|name| name.to_str()).ok_or("invalid copy name")?;
        let name = std::path::Path::new(file).with_extension(format).to_string_lossy().into_owned();
        if name.len() > 255 {
            return Err("copy name exceeds 255 bytes".into());
        }
        let bytes = gridcraft_engine::io::save_bytes(&doc.wb, &name).map_err(|error| error.to_string())?;
        self.host_start_copy(name, bytes)
    }
    pub(crate) fn host_start_copy(&mut self, name: String, bytes: Vec<u8>) -> Result<Value, String> {
        let doc = self.session.active().ok_or("no workbook is open")?;
        self.host_enqueue_write(name, bytes, false, (doc.uid, doc.revision, doc.wb.clone()), SaveDisposition::Copy)
    }
    fn host_enqueue_write(
        &mut self,
        name: String,
        bytes: Vec<u8>,
        save_as: bool,
        owner: (u64, u64, Arc<Workbook>),
        disposition: SaveDisposition,
    ) -> Result<Value, String> {
        let (uid, revision, workbook) = owner;
        if self.pending_host_saves.len() + self.finished_host_saves.len() >= 8 {
            return Err("too many pending host writes".into());
        }
        let held = self.pending_host_saves.iter().map(|s| s.bytes).chain(self.finished_host_saves.iter().map(|(s, _)| s.bytes)).sum::<usize>();
        if bytes.len() > 32 << 20 || held.saturating_add(bytes.len()) > 64 << 20 {
            return Err("host save byte capacity reached".into());
        }
        let writer = self.services.host_save.as_ref().ok_or("no acknowledged host writer")?;
        if disposition == SaveDisposition::Source {
            self.host_unsaved.insert(uid);
        }
        let result = writer(&name, &bytes, save_as, uid, revision, workbook.clone(), disposition);
        let ticket = match result {
            Ok(ticket) => ticket,
            Err(error) => {
                self.host_unsaved.insert(uid);
                self.host_update_dirty();
                return Err(error);
            }
        };
        if self.pending_host_saves.iter().any(|save| save.ticket == ticket) || self.finished_host_saves.iter().any(|(save, _)| save.ticket == ticket)
        {
            self.host_unsaved.insert(uid);
            self.host_update_dirty();
            return Err("duplicate host save ticket".into());
        }
        let active_sheet = workbook.active_sheet();
        self.pending_host_saves.push(PendingSave {
            document: uid,
            ticket,
            revision,
            workbook,
            active_sheet,
            bytes: bytes.len(),
            name,
            close: None,
            disposition,
        });
        self.host_update_dirty();
        Ok(
            json!({"pendingSave":ticket,"documentId":uid,"engineRevision":revision,"disposition":if disposition == SaveDisposition::Copy {"copy"} else {"source"}}),
        )
    }
    pub(crate) fn host_defer_close(&mut self, ticket: u64, quitting: bool, ctx: egui::Context) {
        if let Some(save) = self.pending_host_saves.iter_mut().find(|save| save.ticket == ticket) {
            save.close = Some((quitting, ctx));
        }
    }
    pub(crate) fn host_cancel_deferred_close(&mut self, quitting: bool) {
        let active = self.session.active().map(|doc| doc.uid);
        for save in self.pending_host_saves.iter_mut().chain(self.finished_host_saves.iter_mut().map(|(save, _)| save)) {
            if Some(save.document) == active || (quitting && save.close.as_ref().is_some_and(|(quit, _)| *quit)) {
                save.close = None;
            }
        }
        self.allow_close = false;
    }
    fn host_save_is_current(&self, save: &PendingSave) -> bool {
        self.session.documents().iter().any(|doc| {
            doc.uid == save.document
                && doc.revision == save.revision
                && Arc::ptr_eq(&doc.wb, &save.workbook)
                && doc.wb.active_sheet() == save.active_sheet
        })
    }
    pub fn poll_host_saves(&mut self) {
        for (ticket, outcome) in self.host_saves.take_finished() {
            let Some(i) = self.pending_host_saves.iter().position(|save| save.ticket == ticket) else { continue };
            let save = self.pending_host_saves.remove(i);
            self.finished_host_saves.push((save, outcome));
        }
        // Retain acknowledged Close until all owner writes settle. Baseline adoption and
        // permission to execute that Close are separate: an old failure vetoes its Close,
        // but must not veto a later successful retry of the actual current source snapshot.
        let ready: BTreeSet<_> = self
            .finished_host_saves
            .iter()
            .map(|(s, _)| s.document)
            .filter(|uid| !self.pending_host_saves.iter().any(|s| s.document == *uid))
            .collect();
        for uid in ready {
            let mut group = Vec::new();
            let mut i = 0;
            while i < self.finished_host_saves.len() {
                if self.finished_host_saves[i].0.document == uid {
                    group.push(self.finished_host_saves.remove(i));
                } else {
                    i += 1;
                }
            }
            let drafts = self.host_has_drafts();
            let all_current_success =
                !drafts && group.iter().all(|(save, outcome)| *outcome == SaveOutcome::Saved && self.host_save_is_current(save));
            let close_allowed = all_current_success && !self.host_interaction_busy();
            // Ticket order is admission order, not completion order. A delayed ACK for an
            // earlier Save As must not replace the newer successful save's name/baseline.
            let source = group
                .iter()
                .filter(|(save, outcome)| {
                    !drafts && *outcome == SaveOutcome::Saved && save.disposition == SaveDisposition::Source && self.host_save_is_current(save)
                })
                .max_by_key(|(save, _)| save.ticket);
            if let Some((save, _)) = source {
                let newer_uncertainty = group
                    .iter()
                    .any(|(other, outcome)| other.ticket > save.ticket && (*outcome != SaveOutcome::Saved || !self.host_save_is_current(other)));
                if let Some(doc) = self.session.document_mut_by_uid(uid) {
                    doc.saved = save.workbook.clone();
                    if doc.path.is_none() {
                        doc.title = save.name.clone();
                    }
                }
                if newer_uncertainty {
                    self.host_unsaved.insert(uid);
                } else {
                    self.host_unsaved.remove(&uid);
                }
                if close_allowed
                    && let Some((quitting, ctx)) = group
                        .iter_mut()
                        .filter(|(save, _)| save.close.is_some())
                        .max_by_key(|(save, _)| save.ticket)
                        .and_then(|(save, _)| save.close.take())
                    && let Some(index) = self.session.document_index(uid)
                {
                    self.session.close_document(index);
                    self.follow_active_window();
                    self.after_engine();
                    if quitting {
                        self.continue_quit(&ctx);
                    }
                }
            } else if !all_current_success {
                // Copy-only successes never clear an earlier failed-write latch.
                self.host_unsaved.insert(uid);
            }
        }
        self.host_update_dirty();
    }
    pub fn host_commands(&self, query: &str) -> Value {
        let query = query.to_ascii_lowercase();
        json!(
            self.session
                .commands()
                .into_iter()
                .filter(|command| COMMANDS.contains(&command.id)
                    && (command.id.to_ascii_lowercase().contains(&query) || command.label.to_ascii_lowercase().contains(&query)))
                .map(|mut command| {
                    command.enabled &= !self.host_has_drafts() && !self.host_interaction_busy();
                    command
                })
                .collect::<Vec<_>>()
        )
    }
    pub fn host_execute(&mut self, command: &str, params: &Value) -> Result<Value, String> {
        if !COMMANDS.contains(&command) || !params.is_object() {
            return Err("unsupported host command or argument shape".into());
        }
        if self.host_has_drafts() || self.host_interaction_busy() {
            return Err("resolve owned UI typing/dialogs before a host operation".into());
        }
        if command == "home.insertSheet" && self.session.active().is_some_and(|doc| doc.wb.sheets.len() >= 128) {
            return Err("host sheet insertion is limited to 128 sheets".into());
        }
        validate(command, params)?;
        let result = self.run(command, params.clone())?;
        if result.to_string().len() > 1 << 20 {
            return Err("host response exceeds 1 MiB".into());
        }
        self.host_update_dirty();
        Ok(result)
    }
    pub fn host_inspect(&mut self, params: &Value) -> Result<Value, String> {
        if !params.is_object() {
            return Err("inspection params must be an object".into());
        }
        let doc = self.session.active().ok_or("no workbook is open")?;
        let mut result = json!({"documentId":doc.uid,"engineRevision":doc.revision,"title":doc.title,"dirty":self.host_has_unsaved_documents(),"activeDirty":doc.is_dirty(),"pendingWrites":self.host_pending_saves(),"pendingDrafts":self.host_has_drafts(),"ownedDocuments":self.session.documents().len(),"sheetCount":doc.wb.sheets.len(),"activeSheet":doc.wb.active_sheet(),"sheets":doc.wb.sheets.iter().take(128).enumerate().map(|(i,sh)|json!({"index":i,"name":sh.name,"cells":sh.cells.len()})).collect::<Vec<_>>()});
        let range = params.get("range").and_then(Value::as_str).unwrap_or("A1:D10");
        bounded_range(range)?;
        let mut read = json!({"range":range,"formulas":params.get("formulas").and_then(Value::as_bool).unwrap_or(false)});
        if let Some(sheet) = params.get("sheet") {
            read["sheet"] = sheet.clone();
        }
        result["data"] = self.run("sheet.read", read)?;
        if result.to_string().len() > 1 << 20 {
            return Err("inspection exceeds 1 MiB; read a smaller range".into());
        }
        Ok(result)
    }
    pub fn host_export(&mut self, format: &str) -> Result<Vec<u8>, String> {
        if !["xlsx", "csv", "tsv", "json", "html"].contains(&format) {
            return Err("unsupported export format".into());
        }
        if self.host_has_drafts() || self.host_interaction_busy() {
            return Err("resolve owned drafts/dialogs before exporting".into());
        }
        self.store_view_state();
        let doc = self.session.active().ok_or("no workbook is open")?;
        let bytes = gridcraft_engine::io::save_bytes(&doc.wb, &format!("Book.{format}")).map_err(|error| error.to_string())?;
        if bytes.len() > 32 << 20 {
            return Err("export exceeds 32 MiB".into());
        }
        Ok(bytes)
    }
}
const COMMANDS: &[&str] =
    &["cell.set", "cell.get", "range.setValues", "home.insertSheet", "home.deleteSheet", "sheet.rename", "sheet.activate", "edit.undo", "edit.redo"];
fn bounded_range(range: &str) -> Result<RangeRef, String> {
    let range = RangeRef::parse(range).ok_or("invalid range")?;
    if range.count() > 1024 {
        return Err("host ranges are limited to 1024 cells".into());
    }
    Ok(range)
}
fn validate(command: &str, params: &Value) -> Result<(), String> {
    let allowed: &[&str] = match command {
        "cell.set" => &["cell", "input", "sheet", "array"],
        "cell.get" => &["cell", "sheet"],
        "range.setValues" => &["range", "values", "sheet", "parse"],
        "home.insertSheet" => &["name", "before"],
        "home.deleteSheet" | "sheet.activate" => &["sheet"],
        "sheet.rename" => &["sheet", "name"],
        "edit.undo" | "edit.redo" => &["steps"],
        _ => return Err("unsupported command".into()),
    };
    if params.as_object().is_some_and(|object| object.keys().any(|key| !allowed.contains(&key.as_str()))) {
        return Err("unsupported command parameter".into());
    }
    if params.to_string().len() > 1 << 20 {
        return Err("command exceeds 1 MiB".into());
    }
    if matches!(command, "cell.set" | "cell.get") {
        let cell = params.get("cell").and_then(Value::as_str).ok_or("explicit cell is required")?;
        CellRef::parse(cell).ok_or("invalid cell")?;
    }
    if command == "cell.set" {
        let input = params.get("input").and_then(Value::as_str).ok_or("input is required")?;
        if input.len() > 65536 {
            return Err("cell input exceeds 65536 bytes".into());
        }
    }
    if command == "range.setValues" {
        let range = bounded_range(params.get("range").and_then(Value::as_str).ok_or("explicit range is required")?)?;
        let rows = params.get("values").and_then(Value::as_array).ok_or("values rows are required")?;
        let mut count = 0usize;
        let mut width = 0usize;
        if rows.is_empty() || rows.len() > 64 {
            return Err("choose 1 to 64 value rows".into());
        }
        for row in rows {
            let values = row.as_array().ok_or("each row must be an array")?;
            width = width.max(values.len());
            count = count.saturating_add(values.len());
            if values.is_empty()
                || values.len() > 64
                || count > 1024
                || values.iter().any(|value| value.is_array() || value.is_object() || value.as_str().is_some_and(|text| text.len() > 65536))
            {
                return Err("invalid or oversized value block".into());
            }
        }
        if range.start.row.saturating_add(rows.len() as u32) > gridcraft_engine::core::MAX_ROWS
            || range.start.col.saturating_add(width as u32) > gridcraft_engine::core::MAX_COLS
        {
            return Err("value block exceeds worksheet bounds".into());
        }
    }
    if let Some(name) = params.get("name")
        && name.as_str().is_none_or(|name| name.is_empty() || name.len() > 128)
    {
        return Err("invalid sheet name".into());
    }
    if matches!(command, "edit.undo" | "edit.redo")
        && params.get("steps").is_some_and(|steps| steps.as_u64().is_none_or(|steps| steps == 0 || steps > 100))
    {
        return Err("history steps must be between 1 and 100".into());
    }
    Ok(())
}
#[cfg(test)]
mod tests;
