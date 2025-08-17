import { getConfig } from './getConfig';
import { loadCa } from './loadCa';

export async function loadSubCa() {
  return await loadCa({ subjectName: getConfig().subCaName });
}
