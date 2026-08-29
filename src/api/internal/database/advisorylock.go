package database

// AdvisoryLockKey serialises two operations: adopting a schema, and rotating the
// value that every issued credential is stamped with.
//
// Both change what the database treats as authoritative, and neither may run
// while the other does. They share one key rather than taking one each.
const AdvisoryLockKey int64 = 7013500273095901185
