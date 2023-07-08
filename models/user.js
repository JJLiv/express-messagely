/** User class for message.ly */
const db = require("../db");
const ExpressError = require("../expressError");
const bcrypt = require("bcrypt");
const Message = require("../message");




/** User of the site. */

class User {

  /** register new user -- returns
   *    {username, password, first_name, last_name, phone}
   */

  static async register({username, password, first_name, last_name, phone}) {

  const hashedPassword = await bcrypt.hash(password, BCRYPT_WORK_FACTOR);
  const results = await db.query(`
      INSERT INTO users (username, password, first_name, last_name, phone)
      VALUES ($1, $2, $3, $4, $5)
      RETURNING username`, [username, hashedPassword, first_name, last_name, phone]);
      
      let u = results.rows[0];
      return new User(u.username, u.hashedPassword, u.first_name, u.last_name, u.phone);
   }

  /** Authenticate: is this username/password valid? Returns boolean. */

  static async authenticate(username, password) { 
    const results = await db.query(
      `SELECT username, password
      FROM users
      WHERE username = $1`,
      [username]);

  const user = results.rows[0];
  if (user) {
      if (await bcrypt.compare(password, user.password)) {
          return true;
      }
  } 
  throw new ExpressError("Invalid username/password", 400);

  }

  /** Update last_login_at for user */

  static async updateLoginTimestamp(username) { 
    let last_login_at = Date.now()
    const results = await db.query(
      `UPDATE users SET last_login_at=$1 WHERE username = $2`, 
      [last_login_at, this.username]
    );
  }

  /** All: basic info on all users:
   * [{username, first_name, last_name, phone}, ...] */

  static async all() { 
      const results = await db.query(
        "SELECT username, first_name, last_name, phone FROM users"
        );
        return results.rows.map(u => new User(u.username, u.first_name, u.last_name, u.phone));
  };

  /** Get: get user by username
   *
   * returns {username,
   *          first_name,
   *          last_name,
   *          phone,
   *          join_at,
   *          last_login_at } */

  static async get(username) {
      const results = await db.query(
        `SELECT (username, first_name, last_name, phone, join_at, last_login_at)
        FROM users WHERE username = $1`, 
        [username]);
      if(results.rows.length === 0) {
        throw new ExpressError("User Not Found", 404);
      }
      let u = results.rows[0];
      return new User(username, u.first_name, u.last_name, u.phone, u.join_at, u.last_login_at);
   }

  /** Return messages from this user.
   *
   * [{id, to_user, body, sent_at, read_at}]
   *
   * where to_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesFrom(username) {
    const result = await db.query(
      `SELECT m.id,
              m.from_username,
              f.first_name AS from_first_name,
              f.last_name AS from_last_name,
              f.phone AS from_phone,
              m.to_username,
              t.first_name AS to_first_name,
              t.last_name AS to_last_name,
              t.phone AS to_phone,
              m.body,
              m.sent_at,
              m.read_at
        FROM messages AS m
          JOIN users AS f ON m.from_username = f.username
          JOIN users AS t ON m.to_username = t.username
        WHERE m.from_username = $1`,
      [username]);

  return result.rows.map(m = m.id, m.to_user, m.body, m.sent_at, m.read_at);
  
}
   

  /** Return messages to this user.
   *
   * [{id, from_user, body, sent_at, read_at}]
   *
   * where from_user is
   *   {username, first_name, last_name, phone}
   */

  static async messagesTo(username) { 
    const result = await db.query(
      `SELECT m.id,
              m.from_username,
              f.first_name AS from_first_name,
              f.last_name AS from_last_name,
              f.phone AS from_phone,
              m.to_username,
              t.first_name AS to_first_name,
              t.last_name AS to_last_name,
              t.phone AS to_phone,
              m.body,
              m.sent_at,
              m.read_at
        FROM messages AS m
          JOIN users AS f ON m.from_username = f.username
          JOIN users AS t ON m.to_username = t.username
        WHERE m.to_username = $1`,
      [username]);

  return result.rows.map(m = m.id, m.from_user, m.body, m.sent_at, m.read_at);
  
  }
}


module.exports = User;