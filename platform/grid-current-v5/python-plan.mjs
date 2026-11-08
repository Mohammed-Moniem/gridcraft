// Shared pure startup contract. No interpreter or startup hook is executed here.
import assert from 'node:assert/strict';

export const PYTHON_FLAGS=Object.freeze(['-B','-I','-S']);
export function assertPythonEnvironment(environment) {
  assert(environment&&typeof environment==='object'&&!Array.isArray(environment));
  assert(!Object.keys(environment).some(key=>/^PYTHON|^(?:__PYVENV_LAUNCHER__|VIRTUAL_ENV|CONDA_PREFIX)$/i.test(key)),'Unreviewed Python startup environment');
  return environment;
}
export function assertArchivePlan(plan,archivePath) {
  assert.equal(typeof archivePath,'string');assert(archivePath.endsWith('/archive.py')||archivePath.endsWith('\\archive.py'));
  assert(Array.isArray(plan)&&plan.every(value=>typeof value==='string'));
  assert.deepEqual(plan.slice(0,3),PYTHON_FLAGS,'Archive startup requires -B -I -S before the script');
  assert.equal(plan[3],archivePath,'Archive script identity differs');
  const count={extract:5,'install-tools':4,pack:3}[plan[4]];
  assert(count,'Unknown archive operation');assert.equal(plan.length,4+count,'Unexpected archive arguments');
  return plan;
}
export function archiveArgs(archivePath,operation,...args) {
  return assertArchivePlan([...PYTHON_FLAGS,archivePath,operation,...args],archivePath);
}
export function assertArchiveInvocation(executable,args,environment,pythonPath,archivePath) {
 assert.equal(executable,pythonPath,'Archive interpreter differs');assertArchivePlan(args,archivePath);assertPythonEnvironment(environment);return true;
}
