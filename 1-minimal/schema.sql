CREATE TABLE [users] (
[id] INTEGER NOT NULL PRIMARY KEY AUTOINCREMENT,
[username] VARCHAR(64) UNIQUE NOT NULL,
[password_hash] BLOB(118) NOT NULL
);