use super::*;
use crate::{SaveAnswer, Services};
use gridcraft_engine::Session;
use std::cell::RefCell;
type Write = (u64, u64, u64, Arc<Workbook>, Vec<u8>, bool, SaveDisposition, String);
fn fixture() -> SheetApp {
    let mut session = Session::new();
    session.new_workbook();
    SheetApp::new(session, Services::default())
}
fn writer(app: &mut SheetApp) -> Rc<RefCell<Vec<Write>>> {
    let writes = Rc::new(RefCell::new(Vec::new()));
    let captured = writes.clone();
    let queue = app.host_saves.clone();
    app.services.host_save = Some(Box::new(move |name, bytes, save_as, document, revision, workbook, disposition| {
        let ticket = queue.start()?;
        captured.borrow_mut().push((ticket, document, revision, workbook, bytes.to_vec(), save_as, disposition, name.to_string()));
        Ok(ticket)
    }));
    writes
}
fn set(app: &mut SheetApp, value: &str) {
    app.host_execute("cell.set", &json!({"cell":"A1","input":value})).unwrap();
}
fn value(app: &mut SheetApp) -> Value {
    app.run("cell.get", json!({"cell":"A1"})).unwrap()["value"].clone()
}
fn ack(app: &mut SheetApp, ticket: u64, outcome: SaveOutcome) {
    app.host_saves.finish(ticket, outcome);
    app.poll_host_saves();
}

#[test]
fn clean_save_remains_owned_until_exact_ack() {
    let mut app = fixture();
    let writes = writer(&mut app);
    let uid = app.session.active().unwrap().uid;
    assert!(!app.host_has_unsaved_documents());
    let result = app.run("file.save", json!({})).unwrap();
    assert!(result["pendingSave"].is_u64());
    assert!(app.host_has_unsaved_documents());
    assert!(app.host_dirty_flag.load(Ordering::Relaxed));
    assert_eq!(app.host_pending_saves(), 1);
    app.host_saves.finish(999, SaveOutcome::Saved);
    app.poll_host_saves();
    assert_eq!(app.host_pending_saves(), 1);
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
    assert_eq!(app.session.active().unwrap().uid, uid);
}
#[test]
fn stale_success_does_not_clear_later_human_engine_edits() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "First");
    app.run("file.save", json!({})).unwrap();
    app.run("cell.set", json!({"cell":"A1","input":"Newer human command"})).unwrap();
    let wb = app.session.active().unwrap().wb.clone();
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    assert!(Arc::ptr_eq(&wb, &app.session.active().unwrap().wb));
    assert_eq!(value(&mut app), "Newer human command");
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
}
#[test]
fn failed_clean_save_is_uncertain_until_retry_or_explicit_discard() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Failed);
    assert!(app.host_has_unsaved_documents());
    assert!(app.close_from_host(false).is_err());
    assert!(app.run("file.close", json!({})).unwrap()["pendingClose"].as_bool().unwrap());
    app.dialog = None;
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
}
#[test]
fn parked_dirty_workbook_cannot_be_hidden_by_host_open_or_close() {
    let mut app = fixture();
    set(&mut app, "Owned");
    let uid = app.session.active().unwrap().uid;
    let bytes = app.host_export("xlsx").unwrap();
    app.run("file.new", json!({})).unwrap();
    assert!(!app.session.active().unwrap().is_dirty());
    assert!(app.host_has_unsaved_documents());
    assert!(app.open_from_host("Replacement.xlsx", bytes).is_err());
    assert!(app.close_from_host(true).is_err());
    assert!(app.session.documents().iter().any(|document| document.uid == uid && document.is_dirty()));
}
#[test]
fn pending_save_blocks_human_discard_and_host_replacement() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Pending");
    let bytes = app.host_export("xlsx").unwrap();
    app.run("file.save", json!({})).unwrap();
    assert!(app.run("file.close", json!({"force":true,"document":true})).is_err());
    assert!(app.close_from_host(true).is_err());
    assert!(app.open_from_host("New.xlsx", bytes.clone()).is_err());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    app.open_from_host("New.xlsx", bytes).unwrap();
}
#[test]
fn save_changes_close_waits_for_acknowledged_snapshot() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Close after ACK");
    let uid = app.session.active().unwrap().uid;
    assert!(app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default()));
    assert!(app.session.document_index(uid).is_some());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.session.document_index(uid).is_none());
    assert!(!app.host_has_unsaved_documents());
}
#[test]
fn save_changes_close_preserves_later_edits() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "First");
    app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default());
    set(&mut app, "Later");
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert_eq!(value(&mut app), "Later");
    assert!(app.host_has_unsaved_documents());
}
#[test]
fn overlapping_identical_saves_finish_only_after_last_ack() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Two");
    app.run("file.save", json!({})).unwrap();
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
}
#[test]
fn save_as_uses_host_callback_and_rejects_filesystem_parameters() {
    let mut app = fixture();
    let writes = writer(&mut app);
    assert!(app.run("file.save", json!({"path":"not-created.xlsx"})).is_err());
    app.run("file.saveAs", json!({})).unwrap();
    assert_eq!(writes.borrow().len(), 1);
    assert!(writes.borrow()[0].5);
    assert!(app.session.active().unwrap().path.is_none());
}
#[test]
fn real_formulas_sheets_history_and_xlsx_roundtrip() {
    let mut app = fixture();
    app.host_execute("range.setValues", &json!({"range":"A1","values":[[2,3,"=SUM(A1:B1)"]]})).unwrap();
    assert_eq!(app.run("cell.get", json!({"cell":"C1"})).unwrap()["value"], 5.0);
    app.host_execute("sheet.rename", &json!({"name":"Data"})).unwrap();
    app.host_execute("home.insertSheet", &json!({"name":"Summary"})).unwrap();
    app.host_execute("edit.undo", &json!({})).unwrap();
    app.host_execute("edit.redo", &json!({})).unwrap();
    app.host_execute("sheet.activate", &json!({"sheet":"Data"})).unwrap();
    let bytes = app.host_export("xlsx").unwrap();
    assert!(app.host_has_unsaved_documents());
    let mut reopened = fixture();
    reopened.open_from_host("Roundtrip.xlsx", bytes.clone()).unwrap();
    assert_eq!(reopened.run("cell.get", json!({"cell":"C1","sheet":"Data"})).unwrap()["value"], 5.0);
    if let Ok(dir) = std::env::var("GRIDCRAFT_HOST_FIXTURE_DIR") {
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(std::path::Path::new(&dir).join("synthetic-input.xlsx"), &bytes).unwrap();
    }
}
#[test]
fn command_and_inspection_bounds_refuse_before_mutation() {
    let mut app = fixture();
    let revision = app.session.active().unwrap().revision;
    assert!(app.host_execute("file.open", &json!({"path":"no"})).is_err());
    assert!(app.host_execute("cell.set", &json!({"cell":"ZZZ99999999","input":"x"})).is_err());
    assert!(app.host_execute("range.setValues", &json!({"range":"A:XFD","values":[[1]]})).is_err());
    assert!(app.host_inspect(&json!({"range":"A:XFD"})).is_err());
    assert!(app.host_export("pdf").is_err());
    assert_eq!(app.session.active().unwrap().revision, revision);
}
#[test]
fn save_ticket_has_one_terminal_outcome_and_bounded_capacity() {
    let queue = SaveQueue::default();
    let ticket = queue.start().unwrap();
    queue.finish(ticket, SaveOutcome::Failed);
    queue.finish(ticket, SaveOutcome::Saved);
    assert_eq!(queue.take_finished(), vec![(ticket, SaveOutcome::Failed)]);
    for _ in 0..8 {
        queue.start().unwrap();
    }
    assert!(queue.start().is_err());
}
#[test]
fn wire_clock_tracks_real_snapshots_without_storage_dirty_epoch() {
    let mut app = fixture();
    let writes = writer(&mut app);
    let mut clock = RevisionClock::default();
    app.run("file.save", json!({})).unwrap();
    let captured = writes.borrow();
    let write = &captured[0];
    let snapshot = clock.sync(write.1, write.2, Some(write.3.clone()));
    let (uid, rev, wb) = app.host_document_identity().unwrap();
    assert_eq!(clock.sync(uid, rev, Some(wb)), snapshot);
    ack(&mut app, write.0, SaveOutcome::Saved);
    let (uid, rev, wb) = app.host_document_identity().unwrap();
    assert_eq!(clock.sync(uid, rev, Some(wb)), snapshot);
    drop(captured);
    set(&mut app, "Edited");
    let (uid, rev, wb) = app.host_document_identity().unwrap();
    assert!(clock.sync(uid, rev, Some(wb)) > snapshot);
}
#[test]
fn active_and_parked_ui_drafts_remain_owned_after_stale_ack() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.save", json!({})).unwrap();
    app.begin_edit(Some("Uncommitted".into()), false);
    assert!(app.host_has_drafts());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    assert!(app.editor.is_some());
    assert!(app.host_export("xlsx").is_err());
    // The actual human File New path commits the draft before changing workbooks.
    app.run("file.new", json!({})).unwrap();
    assert!(app.host_has_unsaved_documents());
}

#[test]
fn parked_uncommitted_window_draft_is_owned_even_when_active_workbook_is_clean() {
    let mut app = fixture();
    app.follow_active_window();
    let first = app.session.active_window().unwrap();
    app.run("file.new", json!({})).unwrap();
    let second = app.session.active_window().unwrap();
    app.enter_window(first);
    app.begin_edit(Some("Parked human typing".into()), false);
    app.show_window(second);
    assert!(app.editor.is_none());
    assert_eq!(app.parked_window_with_draft(), Some(first));
    assert!(!app.session.active().unwrap().is_dirty());
    assert!(app.host_has_unsaved_documents());
    let bytes = fixture().host_export("xlsx").unwrap();
    assert!(app.open_from_host("Replace.xlsx", bytes).is_err());
    assert!(app.close_from_host(true).is_err());
    app.show_window(first);
    assert_eq!(app.editor.as_ref().unwrap().text, "Parked human typing");
}

#[test]
fn acknowledged_parked_owner_settles_without_switching_visible_or_recent_window() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Owner A");
    let first = app.session.active().unwrap().uid;
    app.run("file.save", json!({})).unwrap();
    app.run("file.new", json!({})).unwrap();
    let visible = app.session.active_window();
    let second = app.session.active().unwrap().uid;
    assert_ne!(first, second);
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert_eq!(app.session.active_window(), visible);
    assert_eq!(app.session.active().unwrap().uid, second);
    assert!(!app.session.documents().iter().find(|doc| doc.uid == first).unwrap().is_dirty());
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn human_sheet_switch_changes_wire_context_and_cannot_acknowledge_the_old_view_snapshot() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("home.insertSheet", json!({"name":"Second"})).unwrap();
    app.run("file.save", json!({})).unwrap();
    let (uid, revision, workbook) = app.host_document_identity().unwrap();
    let mut clock = RevisionClock::default();
    let before = clock.sync(uid, revision, Some(workbook.clone()));
    app.run("sheet.activate", json!({"sheet":0})).unwrap();
    let (uid, after_revision, after) = app.host_document_identity().unwrap();
    assert_eq!(revision, after_revision);
    assert!(Arc::ptr_eq(&workbook, &after), "Grid changes active_sheet in place, not by replacing the Arc");
    assert!(clock.sync(uid, after_revision, Some(after)) > before);
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn normal_host_save_preserves_carried_vba_bytes_in_a_macro_enabled_package() {
    let mut app = fixture();
    let writes = writer(&mut app);
    let original = Arc::new(vec![0, 1, 2, 3, 4, 5]);
    Arc::make_mut(&mut app.session.active_mut().unwrap().wb).vba_project = Some(original.clone());
    app.run("file.save", json!({})).unwrap();
    let bytes = writes.borrow()[0].4.clone();
    let mut reopened = fixture();
    reopened.open_from_host("Synthetic.xlsm", bytes).unwrap();
    assert_eq!(reopened.session.active().unwrap().wb.vba_project.as_deref(), Some(original.as_ref()));
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
    assert!(app.session.active().unwrap().title.ends_with(".xlsm"));
}

#[test]
fn existing_backstage_exports_use_acknowledged_copies_without_adopting_or_cleaning_source() {
    for format in ["csv", "html", "pdf"] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "ExportMarker");
        let title = app.session.active().unwrap().title.clone();
        let saved = app.session.active().unwrap().saved.clone();
        // Exactly the production Backstage helper, with no legacy download installed.
        assert!(crate::backstage::export_as(&mut app, format), "{format}: {:?}", app.message);
        let write = writes.borrow()[0].clone();
        assert_eq!(write.6, SaveDisposition::Copy);
        assert!(!write.5);
        assert!(write.7.ends_with(&format!(".{format}")));
        if format == "pdf" {
            assert!(write.4.starts_with(b"%PDF"));
        } else {
            assert!(String::from_utf8(write.4).unwrap().contains("ExportMarker"));
        }
        assert!(app.close_from_host(true).is_err());
        ack(&mut app, write.0, SaveOutcome::Saved);
        let document = app.session.active().unwrap();
        assert!(document.is_dirty());
        assert!(Arc::ptr_eq(&document.saved, &saved));
        assert_eq!(document.title, title);
        assert!(document.path.is_none());
        assert!(app.host_has_unsaved_documents());
    }
}

#[test]
fn share_save_copy_preserves_source_name_path_and_baseline_even_when_clean() {
    let mut app = fixture();
    let writes = writer(&mut app);
    let title = app.session.active().unwrap().title.clone();
    let saved = app.session.active().unwrap().saved.clone();
    let input = app.host_export("xlsx").unwrap();
    app.host_export_copy("xlsx", Some("some/folder/Shared.xlsx")).unwrap();
    assert_eq!(writes.borrow()[0].7, "Shared.xlsx");
    assert_eq!(writes.borrow()[0].6, SaveDisposition::Copy);
    assert!(app.host_has_unsaved_documents());
    assert!(app.open_from_host("Replacement.xlsx", input).is_err());
    assert!(app.run("file.close", json!({"force":true})).is_err());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert_eq!(app.session.active().unwrap().title, title);
    assert!(app.session.active().unwrap().path.is_none());
    assert!(Arc::ptr_eq(&app.session.active().unwrap().saved, &saved));
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn failed_or_stale_copy_remains_owned_and_a_copy_cannot_clear_prior_uncertainty() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.exportCsv", json!({})).unwrap();
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Failed);
    assert!(app.host_has_unsaved_documents());
    assert!(app.close_from_host(false).is_err());
    app.run("file.exportHtml", json!({})).unwrap();
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[2].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
    app.run("file.exportCsv", json!({})).unwrap();
    set(&mut app, "Later owned edit");
    ack(&mut app, writes.borrow()[3].0, SaveOutcome::Saved);
    assert!(app.host_has_unsaved_documents());
    assert_eq!(value(&mut app), "Later owned edit");
}

#[test]
fn export_admission_failure_has_no_legacy_fallback_or_filesystem_effect() {
    let mut app = fixture();
    let downloads = Rc::new(RefCell::new(0));
    let count = downloads.clone();
    app.services.download = Some(Box::new(move |_, _| *count.borrow_mut() += 1));
    app.services.host_save = Some(Box::new(|_, _, _, _, _, _, _| Err("host unavailable".into())));
    assert!(!crate::backstage::export_as(&mut app, "csv"));
    assert!(app.host_has_unsaved_documents());
    assert_eq!(*downloads.borrow(), 0);
    for command in ["file.exportCsv", "file.exportHtml", "file.exportPdf"] {
        assert!(app.run(command, json!({"path":"must-not-be-created"})).is_err());
    }
}

#[test]
fn save_changes_close_retains_earlier_ack_until_concurrent_identical_save_finishes() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Close exact owner after both");
    let uid = app.session.active().unwrap().uid;
    assert!(app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default()));
    app.run("file.save", json!({})).unwrap();
    assert_eq!(writes.borrow()[0].2, writes.borrow()[1].2);
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.session.document_index(uid).is_some());
    assert_eq!(app.host_pending_saves(), 1);
    assert!(app.host_has_unsaved_documents());
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    assert!(app.session.document_index(uid).is_none());
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn concurrent_copy_finishes_deferred_source_close_but_failure_or_new_edit_vetoes_it() {
    for veto in ["none", "failure", "edit"] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Close owner");
        let uid = app.session.active().unwrap().uid;
        app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default());
        app.run("file.exportCsv", json!({})).unwrap();
        ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
        if veto == "edit" {
            set(&mut app, "Newer");
        }
        ack(&mut app, writes.borrow()[1].0, if veto == "failure" { SaveOutcome::Failed } else { SaveOutcome::Saved });
        assert_eq!(app.session.document_index(uid).is_some(), veto != "none");
        assert_eq!(app.host_has_unsaved_documents(), veto != "none");
    }
}

#[test]
fn acknowledged_but_waiting_groups_remain_bounded() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.save", json!({})).unwrap();
    for _ in 1..8 {
        app.run("file.save", json!({})).unwrap();
        let ticket = writes.borrow().last().unwrap().0;
        ack(&mut app, ticket, SaveOutcome::Saved);
    }
    assert_eq!(app.finished_host_saves.len(), 7);
    assert!(app.run("file.save", json!({})).is_err());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.finished_host_saves.is_empty());
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn ordinary_unhosted_browser_exports_still_use_download_callback() {
    let mut app = fixture();
    let downloads = Rc::new(RefCell::new(Vec::new()));
    let capture = downloads.clone();
    app.services.download = Some(Box::new(move |name, bytes| capture.borrow_mut().push((name.to_string(), bytes.to_vec()))));
    for format in ["csv", "html", "pdf"] {
        assert!(crate::backstage::export_as(&mut app, format));
    }
    assert_eq!(downloads.borrow().len(), 3);
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn clean_copy_pending_blocks_quit_and_discard_until_write_settles() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.exportCsv", json!({})).unwrap();
    let ctx = egui::Context::default();
    app.request_quit(&ctx);
    assert!(!app.allow_close);
    app.answer_save_changes(SaveAnswer::DontSave, true, &ctx);
    assert!(!app.allow_close);
    assert!(app.session.active().is_some());
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    app.request_quit(&ctx);
    assert!(app.allow_close);
}

#[test]
fn queued_failed_write_then_immediate_successful_retry_cleans_without_third_save() {
    for order in ["queued-failure", "retry-ack-first"] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Immediate retry");
        app.run("file.save", json!({})).unwrap();
        let first = writes.borrow()[0].0;
        if order == "queued-failure" {
            // The SDK has already rejected save A, but the next UI logic frame has not
            // consumed its queued failure when the caller immediately starts retry B.
            app.host_saves.finish(first, SaveOutcome::Failed);
        }
        app.run("file.save", json!({})).unwrap();
        let second = writes.borrow()[1].0;
        assert_eq!(writes.borrow()[0].2, writes.borrow()[1].2);
        assert!(Arc::ptr_eq(&writes.borrow()[0].3, &writes.borrow()[1].3));
        if order == "queued-failure" {
            ack(&mut app, second, SaveOutcome::Saved);
        } else {
            ack(&mut app, second, SaveOutcome::Saved);
            assert!(app.host_has_unsaved_documents());
            ack(&mut app, first, SaveOutcome::Failed);
        }
        assert_eq!(app.host_pending_saves(), 0);
        assert!(!app.host_has_unsaved_documents(), "{order}");
        assert!(!app.session.active().unwrap().is_dirty());
        assert_eq!(value(&mut app), "Immediate retry");
        assert_eq!(writes.borrow().len(), 2);
    }
}

#[test]
fn earlier_failed_copy_is_resolved_by_later_current_source_save_in_either_ack_order() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Source survived failed export");
        app.run("file.exportCsv", json!({})).unwrap();
        let copy = writes.borrow()[0].0;
        app.run("file.save", json!({})).unwrap();
        let source = writes.borrow()[1].0;
        if reverse {
            ack(&mut app, source, SaveOutcome::Saved);
            ack(&mut app, copy, SaveOutcome::Failed);
        } else {
            app.host_saves.finish(copy, SaveOutcome::Failed);
            ack(&mut app, source, SaveOutcome::Saved);
        }
        assert!(!app.host_has_unsaved_documents());
        assert!(!app.session.active().unwrap().is_dirty());
        assert!(app.session.active().unwrap().title.ends_with(".xlsx"));
    }
}

#[test]
fn newer_failed_copy_retains_uncertainty_but_does_not_undo_persisted_source_baseline() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Saved source, failed later export");
        app.run("file.save", json!({})).unwrap();
        app.run("file.exportHtml", json!({})).unwrap();
        let (source, copy) = (writes.borrow()[0].0, writes.borrow()[1].0);
        if reverse {
            ack(&mut app, copy, SaveOutcome::Failed);
            ack(&mut app, source, SaveOutcome::Saved);
        } else {
            ack(&mut app, source, SaveOutcome::Saved);
            ack(&mut app, copy, SaveOutcome::Failed);
        }
        assert!(!app.session.active().unwrap().is_dirty(), "acknowledged source bytes are still the baseline");
        assert!(app.host_has_unsaved_documents(), "the later failed copy remains owned");
        assert!(app.close_from_host(false).is_err());
        app.run("file.exportCsv", json!({})).unwrap();
        ack(&mut app, writes.borrow()[2].0, SaveOutcome::Saved);
        assert!(app.host_has_unsaved_documents(), "a successful copy cannot settle failed-write ownership");
        app.run("file.save", json!({})).unwrap();
        ack(&mut app, writes.borrow()[3].0, SaveOutcome::Saved);
        assert!(!app.host_has_unsaved_documents());
    }
}

#[test]
fn newest_successful_save_identity_wins_over_completion_order() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Same workbook snapshot, distinct name hints");
        app.session.active_mut().unwrap().title = "Earlier.xlsx".into();
        app.run("file.saveAs", json!({})).unwrap();
        app.session.active_mut().unwrap().title = "Latest.xlsx".into();
        app.run("file.saveAs", json!({})).unwrap();
        let (first, second) = (writes.borrow()[0].0, writes.borrow()[1].0);
        assert_eq!(writes.borrow()[0].7, "Earlier.xlsx");
        assert_eq!(writes.borrow()[1].7, "Latest.xlsx");
        if reverse {
            ack(&mut app, second, SaveOutcome::Saved);
            ack(&mut app, first, SaveOutcome::Saved);
        } else {
            ack(&mut app, first, SaveOutcome::Saved);
            ack(&mut app, second, SaveOutcome::Saved);
        }
        assert_eq!(app.session.active().unwrap().title, "Latest.xlsx");
        assert!(app.session.active().unwrap().path.is_none());
        assert!(!app.host_has_unsaved_documents());
    }
}

#[test]
fn failed_close_save_cannot_revive_close_when_its_immediate_retry_succeeds() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Keep this owner open after failed Close save");
        let uid = app.session.active().unwrap().uid;
        app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default());
        let close = writes.borrow()[0].0;
        if !reverse {
            app.host_saves.finish(close, SaveOutcome::Failed);
        }
        app.run("file.save", json!({})).unwrap();
        ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
        if reverse {
            ack(&mut app, close, SaveOutcome::Failed);
        }
        assert!(app.session.document_index(uid).is_some());
        assert!(!app.host_has_unsaved_documents(), "successful retry saves bytes without granting the failed Close");
    }
}

#[test]
fn newer_failed_source_vetoes_deferred_close_and_remains_owned_until_a_fresh_retry() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "Pending Close");
    let uid = app.session.active().unwrap().uid;
    app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default());
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Failed);
    assert!(app.session.document_index(uid).is_some());
    assert!(app.host_has_unsaved_documents());
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[2].0, SaveOutcome::Saved);
    assert!(app.session.document_index(uid).is_some(), "old Close action does not revive on later saves");
    assert!(!app.host_has_unsaved_documents());
}

#[test]
fn cancelling_the_prompt_clears_pending_and_held_close_intents_without_cancelling_storage() {
    for held in [false, true] {
        for quitting in [false, true] {
            let mut app = fixture();
            let writes = writer(&mut app);
            let ctx = egui::Context::default();
            set(&mut app, "Cancel Close, finish saving");
            let uid = app.session.active().unwrap().uid;
            app.answer_save_changes(SaveAnswer::Save, quitting, &ctx);
            app.run("file.save", json!({})).unwrap();
            if held {
                ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
            }
            app.answer_save_changes(SaveAnswer::Cancel, quitting, &ctx);
            if !held {
                ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
            }
            ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
            assert!(app.session.document_index(uid).is_some());
            assert!(!app.allow_close);
            assert!(!app.host_has_unsaved_documents());
        }
    }
}

#[test]
fn overlapping_successful_close_saves_close_once_in_both_ack_orders() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Close only after both successful writes");
        let uid = app.session.active().unwrap().uid;
        app.answer_save_changes(SaveAnswer::Save, false, &egui::Context::default());
        app.run("file.save", json!({})).unwrap();
        let (first, second) = (writes.borrow()[0].0, writes.borrow()[1].0);
        let order = if reverse { [second, first] } else { [first, second] };
        ack(&mut app, order[0], SaveOutcome::Saved);
        assert!(app.session.document_index(uid).is_some());
        ack(&mut app, order[1], SaveOutcome::Saved);
        assert!(app.session.document_index(uid).is_none());
        ack(&mut app, first, SaveOutcome::Saved);
        ack(&mut app, second, SaveOutcome::Saved);
        assert!(!app.host_has_unsaved_documents());
    }
}

#[test]
fn successful_current_source_covers_older_stale_snapshot_but_keeps_newer_edits_owned() {
    let mut app = fixture();
    let writes = writer(&mut app);
    set(&mut app, "First snapshot");
    app.run("file.save", json!({})).unwrap();
    set(&mut app, "Current persisted snapshot");
    app.run("file.save", json!({})).unwrap();
    ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(!app.host_has_unsaved_documents());
    assert_eq!(value(&mut app), "Current persisted snapshot");
    app.run("file.save", json!({})).unwrap();
    app.host_saves.finish(writes.borrow()[2].0, SaveOutcome::Failed);
    app.run("file.save", json!({})).unwrap();
    set(&mut app, "Newer unsaved human edit");
    ack(&mut app, writes.borrow()[3].0, SaveOutcome::Saved);
    assert!(app.session.active().unwrap().is_dirty());
    assert!(app.host_has_unsaved_documents());
    assert_eq!(value(&mut app), "Newer unsaved human edit");
}

#[test]
fn actual_escape_and_control_cancel_routes_clear_retained_save_changes_close() {
    for route in ["escape", "control"] {
        let mut app = fixture();
        let writes = writer(&mut app);
        let ctx = egui::Context::default();
        set(&mut app, "Cancel the actual Save Changes prompt");
        let uid = app.session.active().unwrap().uid;
        app.answer_save_changes(SaveAnswer::Save, false, &ctx);
        app.run("file.save", json!({})).unwrap();
        ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
        app.open_dialog("saveChanges", json!({"title":"Test owner","quit":false}));
        if route == "control" {
            let crate::control::Outcome::Done(reply) = crate::control::handle(&mut app, &ctx, "ui.dialog.cancel", &json!({})) else {
                panic!("dialog cancellation is synchronous");
            };
            assert_eq!(reply["ok"], true);
        } else {
            ctx.set_fonts(crate::theme::pinned_font_definitions());
            let raw = egui::RawInput {
                screen_rect: Some(egui::Rect::from_min_size(egui::Pos2::ZERO, egui::vec2(800.0, 600.0))),
                max_texture_side: Some(8192),
                events: vec![egui::Event::Key {
                    key: egui::Key::Escape,
                    physical_key: None,
                    pressed: true,
                    repeat: false,
                    modifiers: egui::Modifiers::NONE,
                }],
                ..Default::default()
            };
            let mut output = ctx.run_ui(raw, |ui| crate::dialogs::show(&mut app, ui.ctx()));
            output.textures_delta.clear();
        }
        assert!(app.dialog.is_none(), "{route}");
        ack(&mut app, writes.borrow()[1].0, SaveOutcome::Saved);
        assert!(app.session.document_index(uid).is_some());
        assert!(!app.host_has_unsaved_documents());
    }
}

#[test]
fn ack_before_prompt_input_cannot_close_an_owner_with_a_new_live_dialog() {
    let mut app = fixture();
    let writes = writer(&mut app);
    let ctx = egui::Context::default();
    set(&mut app, "A new prompt owns the interaction");
    let uid = app.session.active().unwrap().uid;
    app.answer_save_changes(SaveAnswer::Save, false, &ctx);
    app.open_dialog("saveChanges", json!({"title":"Live prompt","quit":false}));
    // app.logic polls storage before drawing this frame's Escape/Cancel input. Do not
    // remove the live prompt/owner during that earlier phase of the same frame.
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.session.document_index(uid).is_some());
    assert!(app.dialog.is_some());
    assert!(!app.host_has_unsaved_documents());
    app.answer_save_changes(SaveAnswer::Cancel, false, &ctx);
    app.dialog = None;
    app.poll_host_saves();
    assert!(app.session.document_index(uid).is_some());
}

#[test]
fn latest_retained_close_intent_controls_quit_continuation_in_both_ack_orders() {
    for reverse in [false, true] {
        let mut app = fixture();
        let writes = writer(&mut app);
        set(&mut app, "Other dirty owner");
        let other = app.session.active().unwrap().uid;
        app.run("file.new", json!({})).unwrap();
        set(&mut app, "Owner requested close then quit");
        let closing = app.session.active().unwrap().uid;
        let ctx = egui::Context::default();
        app.answer_save_changes(SaveAnswer::Save, false, &ctx);
        app.answer_save_changes(SaveAnswer::Save, true, &ctx);
        let (first, second) = (writes.borrow()[0].0, writes.borrow()[1].0);
        let order = if reverse { [second, first] } else { [first, second] };
        ack(&mut app, order[0], SaveOutcome::Saved);
        ack(&mut app, order[1], SaveOutcome::Saved);
        assert!(app.session.document_index(closing).is_none());
        assert_eq!(app.session.active().unwrap().uid, other);
        let prompt = app.dialog.as_ref().expect("the later Quit intent must ask about the other dirty owner");
        assert_eq!(prompt.name, "saveChanges");
        assert_eq!(prompt.values.get("quit"), Some(&json!(true)));
        assert!(!app.allow_close);
    }
}

#[test]
fn clean_copy_ack_does_not_create_uncertainty_merely_because_a_dialog_is_open() {
    let mut app = fixture();
    let writes = writer(&mut app);
    app.run("file.exportCsv", json!({})).unwrap();
    app.open_dialog("saveCopy", json!({"format":"html"}));
    ack(&mut app, writes.borrow()[0].0, SaveOutcome::Saved);
    assert!(app.host_interaction_busy());
    assert!(app.dialog.is_some());
    assert!(!app.session.active().unwrap().is_dirty());
    assert!(!app.host_has_unsaved_documents());
    assert!(app.close_from_host(false).is_err(), "the existing dialog is still owned independently of storage");
}
