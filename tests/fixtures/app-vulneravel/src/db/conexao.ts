import mysql from 'mysql2/promise';

export const pool = mysql.createPool({
  host: 'localhost',
  user: 'root',
  password: 'root123',
  database: 'escola',
  multipleStatements: true,
});

export const urlBackup = 'mysql://admin:Sup3rSecreta@db.interno:3306/escola';
