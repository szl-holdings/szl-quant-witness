/** Append using the opened file identity, never a checked-and-reopened path.
 * The output directory remains caller-owned and the observer's existing
 * single-writer discipline is required; this is not a filesystem sandbox.
 */
import fs from 'node:fs';

export const OBSERVATION_HEADER = '# Observations — second-observer gossip log\n\n'
  + '| observed (UTC) | head seq | verdict | live tree size | file |\n'
  + '|---|---|---|---|---|\n';

export function appendObservationIndex(path, row) {
  // O_NOFOLLOW is additional protection where available. The descriptor and
  // post-open identity check also protect platforms that do not expose it.
  const flags = fs.constants.O_WRONLY | fs.constants.O_APPEND
    | (fs.constants.O_NOFOLLOW ?? 0);
  let fd;
  try {
    fd = fs.openSync(path, 'ax', 0o600);
  } catch (error) {
    if (error.code !== 'EEXIST') throw error;
    // Never create through an existing/dangling symlink on platforms without
    // O_NOFOLLOW. If a concurrent writer removed the name, fail instead.
    fd = fs.openSync(path, flags);
  }
  try {
    // BigInt identities avoid rounding Windows' 64-bit file indices.
    const opened = fs.fstatSync(fd, { bigint: true });
    const named = fs.lstatSync(path, { bigint: true });
    if (!opened.isFile() || !named.isFile()
        || opened.dev !== named.dev || opened.ino !== named.ino
        || opened.nlink !== 1n) {
      throw new Error('observation index must be one regular file without aliases');
    }
    // A later pathname replacement cannot redirect a write through this fd.
    fs.writeFileSync(fd, (opened.size === 0n ? OBSERVATION_HEADER : '') + row);
  } finally {
    fs.closeSync(fd);
  }
}
