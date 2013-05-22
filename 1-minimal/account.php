<?php
/** name of the database file */
define('DB_FILENAME', 'account.db');

/** schema file */
define('SCHEMA_FILENAME', 'schema.sql');

/* TODO: Allow define of POST, GET, and SESSION variables */
/* TODO: Allow registration to be disabled */

/**
 * Handles login, logout, registration and session.
 */
class Account {
	private $database	= null;		// database connection
	private $logged_in 	= false;	// if the user is logged in
	private $username	= null;		// username
	
	const SUCCESS			= false;
	const BAD_USERNAME 		= 1;
	const BAD_PASSWORD 		= 2;
	const DATABASE_ERROR 	= 3;
	const INCOMPLETE_DATA	= 4;
	const USERNAME_TAKEN	= 5;
	
	/**
     * the function "__construct()" automatically starts whenever an object of this class is created,
     * you know, when you do "$account = new Account();"
     */    
    public function __construct() {
		session_start();
		
		// if user tried to log out
		if(isset($_GET['logout'])) {
			$this->Logout();
		}
		// if user has an active session on the server
        elseif (!empty($_SESSION['username']) && ($_SESSION['logged_in'] == 1)) {
			$this->loginSession();
		}
	}
	
	private function openDatabase() {
		try {
			$create_db = false;
			if(!file_exists(DB_FILENAME)) {
				$create_db = true;
			}
			$this->database = new PDO('sqlite:'.DB_FILENAME);
			if($create_db) {
				$this->database->exec(file_get_contents(SCHEMA_FILENAME));
			}
			$this->database->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
			$this->database->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
		} catch (PDOException $e) {
			return false;
		}
		return true;
	}
	
	private function loginSession() {
		$this->logged_in = true;
		$this->username = $_SESSION['username'];
	}
	
	/**
	 * Returns true if there is a form login attempt pending. Call login to process this.
	 */
	public function isLoggingIn() {
		return isset($_POST["login"]);
	}
	
	/**
	 * Performs a pending login, returns false on success, otherwise returns a error code.
	 */
	public function login() {
		if (empty($_POST['username']) || empty($_POST['password']))
			return self::INCOMPLETE_DATA;
			//TODO throw incomplete login data error
	
		if($this->openDatabase()) {
			//lookup user in the database
			$sql = 'SELECT username, password_hash FROM users WHERE username = ?;';
			$sql = $this->database->prepare($sql);
			$sql->execute(array($_POST['username']));
			
			// if we can get a result object, then the user exists
			if( $result = $sql->fetchObject() ) {
				//check the password
				if (crypt($_POST['password'], $result->password_hash) == $result->password_hash) {
					// write user data into a session
					$_SESSION['username'] = $result->username;
					$_SESSION['logged_in'] = true;
					$this->username = $result->username;
					$this->logged_in = true; 
				} else {
					return self::BAD_PASSWORD;
				}
			} else {
				return self::BAD_USERNAME;
			}
			$this->database = null;
		} else {
			return self::DATABASE_ERROR;
		}
		return self::SUCCESS;
	}
	
	/**
	 * Returns true if there is a registration attempt pending. Call register to process this.
	 */
	public function isRegistering() {
		return isset($_POST["register"]);
	}
	
	/**
	 * Performs a pending registration, returns false on success, otherwise returns a error code.
	 */
	public function register() {
		if(empty($_POST['username']))
			return self::INCOMPLETE_DATA;
		if(empty($_POST['password']) || empty($_POST['password_repeat']))
			return self::INCOMPLETE_DATA;
		if($_POST['password'] !== $_POST['password_repeat'])
			return self::BAD_PASSWORD;
		if(strlen($_POST['username']) > 64)
			return self::BAD_USERNAME;
		//alphanumeric and underscore   3 to 64 characters
		if(!preg_match('/^[_a-zA-Z0-9]{3,64}$/', $_POST['username']))
			return self::BAD_USERNAME;
	
		if($this->openDatabase()) {
			//truncate password to 128 characters, anything more is a bit silly imho
			$password = substr($_POST['password'], 0, 128);
			//create a random hex string for our salt
			$salt = unpack('H*', mcrypt_create_iv(CRYPT_SALT_LENGTH >> 1, MCRYPT_DEV_URANDOM))[1];
			//SHA-512
			$algorithm = '$6$rounds=5000$';
			//create our hash
			$hash = crypt($password, $algorithm . $salt);
			
			
			$sql = 'SELECT * FROM users WHERE username = ?;';
			$sql = $this->database->prepare($sql);
			$sql->execute(array($_POST['username']));
			
			if($sql->fetch(PDO::FETCH_NUM) === false) { 
				//username is not taken, write new data
				$sql = 'INSERT INTO users (username, password_hash) VALUES(?, ?);';
				$sql = $this->database->prepare($sql);
				$sql->execute(array($_POST['username'],$hash));
				
				if ($sql->rowCount() != 1) {
					//account creation failure
					return self::DATABASE_ERROR;
				}
			} else {
				return self::USERNAME_TAKEN;
			}
			$this->database = null;
		} else {
			return self::DATABASE_ERROR;
		}
		
		return self::SUCCESS;
	}
	
	/**
     * Perform a logout
     */
    public function logout() {
            $_SESSION = array();
            session_destroy();
            $this->logged_in = false;
    }
	
	/**
	 * Returns true if a user is currently logged in.
	 */
	public function isLoggedIn() {
		return $this->logged_in;
	}
	
	/**
	 * Returns the username of the currently logged in user, null otherwise.
	 */
	public function getUsername() {
		return $this->username;
	}
}