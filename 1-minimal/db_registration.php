<?php

/**
 * class Registration
 * handles the user registration
 * 
 * @author Panique <panique@web.de>
 * @version 1.0
 */
class Registration {

    private     $db_connection              = null;                     // database connection   
    
    private     $user_name                  = "";                       // user's name
    private     $user_email                 = "";                       // user's email
    private     $user_password              = "";                       // user's password (what comes from POST)
    private     $user_password_hash         = "";                       // user's hashed and salted password
    
    public      $registration_successful    = false;

    public      $errors                     = array();                  // collection of error messages
    public      $messages                   = array();                  // collection of success / neutral messages
    
    
    /**
     * the function "__construct()" automatically starts whenever an object of this class is created,
     * you know, when you do "$login = new Login();"
     */    
    public function __construct() {
        
		if (isset($_POST["register"])) {
			
			$this->registerNewUser();
			
		}        
    }

    /**
     * registerNewUser
     * 
     * handles the entire registration process. checks all error possibilities, and creates a new user in the database if
     * everything is fine
     */
    private function registerNewUser() {
        
        if (empty($_POST['user_name'])) {
          
            $this->errors[] = "Empty Username";

        } elseif (empty($_POST['user_password_new']) || empty($_POST['user_password_repeat'])) {
          
            $this->errors[] = "Empty Password";            
            
        } elseif ($_POST['user_password_new'] !== $_POST['user_password_repeat']) {
          
            $this->errors[] = "Password and password repeat are not the same";   
            
        } elseif (strlen($_POST['user_name']) > 64) {
            
            $this->errors[] = "Username cannot be longer than 64 characters";
                        
        } elseif (!preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])) {
            
            $this->errors[] = "Username does not fit the name sheme: only a-Z and numbers are allowed, 2 to 64 characters";
            
        } elseif (empty($_POST['user_email'])) {
            
            $this->errors[] = "Email cannot be empty";
            
        } elseif (strlen($_POST['user_email']) > 64) {
            
            $this->errors[] = "Email cannot be longer than 64 characters";
            
        } elseif (!filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)) {
            
            $this->errors[] = "Your email adress is not in a valid email format";
        
        } elseif (!empty($_POST['user_name'])
                  && strlen($_POST['user_name']) <= 64
                  && preg_match('/^[a-z\d]{2,64}$/i', $_POST['user_name'])
                  && !empty($_POST['user_email'])
                  && strlen($_POST['user_email']) <= 64
                  && filter_var($_POST['user_email'], FILTER_VALIDATE_EMAIL)
                  && !empty($_POST['user_password_new']) 
                  && !empty($_POST['user_password_repeat']) 
                  && ($_POST['user_password_new'] === $_POST['user_password_repeat'])) {
            
            // TODO: the above check is redundand, but from a developer's perspective it makes clear
            // what exactly we want to reach to go into this if-block

            // creating a database connection
			try {
			
				$create_db = false;
				
				if(!file_exists(DB_FILENAME))
					$create_db = true;
					
				$this->db_connection = new PDO('sqlite:'.DB_FILENAME);
				
				if($create_db)
					$this->db_connection->exec(file_get_contents('schema.sql'));
				
				$this->db_connection->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
				
				$this->db_connection->setAttribute(PDO::ATTR_EMULATE_PREPARES, false);
				
			} catch (PDOException $e) {
			
				//$this->errors[] = "Sorry, no database connection.";
				$this->errors[] = $e;
				
				return;
			}
			
            // if no connection errors (= working database connection)

			// cut password to 1024 chars to prevent too much calculation
			$this->user_password        = substr($_POST['user_password_new'], 0, 1024);

			/* 
			 * get_salt()
			 * generate random string "salt", a string to "encrypt" the password hash
			 * this is a basic salt, you might replace this with a more advanced function
			 * @see http://en.wikipedia.org/wiki/Salt_(cryptography)
			 */
			function get_salt($length) {

				$options = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789./';
				$salt = '';

				for ($i = 0; $i <= $length; $i ++) {
					$options = str_shuffle ( $options );
					$salt .= $options [rand ( 0, 63 )];
				}
				return $salt;
			}

			// getting the max salt length on your system (usually 123 characters on linux)
			$max_salt = CRYPT_SALT_LENGTH;

			// hard to explain, this part of the upcoming hash string is some kind of parameter, defining
			// the intensity of calculation. we are using the SHA-512 algorithm here, please see
			// @see php.net/manual/en/function.crypt.php
			// for more information.
			$hashing_algorithm = '$6$rounds=5000$';

			//get the longest salt, could set to 22 crypt ignores extra data
			$salt = get_salt($max_salt);

			//append salt data to the password, and crypt using salt, results in a 118 character output
			$this->user_password_hash = crypt($this->user_password, $hashing_algorithm.$salt);

			// check if user already exists
			$statement = $this->db_connection->prepare('SELECT * FROM users WHERE user_name = :username;');
			$statement->execute(array('username' => $_POST['user_name']));
			
			if ($statement->rowCount() == 1) {

				$this->errors[] = "Sorry, that user name is already taken.<br/>Please choose another one.";

			} else {

				// write new users data into database
				$statement = $this->db_connection->prepare("INSERT INTO users (user_name, user_password_hash, user_email) VALUES(:username, :hash, :email);");
				$statement->execute(
					array(
						'username' => $_POST['user_name'],
						'hash' => $this->user_password_hash,
						'email' => $_POST['user_email']
						)
					);

				if ($statement->rowCount() == 1) {

					$this->messages[] = "Your account has been created successfully. You can now log in.";
					$this->registration_successful = true;

				} else {

					$this->errors[] = "Sorry, your registration failed. Please go back and try again.";

				}
			}
            
        } else {
            
            $this->errors[] = "An unknown error occured.";
            
        }
        
    }

}