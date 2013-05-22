<?php

require 'account.php';

$account = new Account();

if($account->isLoggingIn()) {
	//prints the return status of the login
	print_r($account->login());
}

if($account->isRegistering()) {
	//prints the return status of the register
	print_r($account->register());
}

if($account->isLoggedIn()) {
	echo '<h3>Welcome '.$account->getUsername().'</h3>';
	echo '<a href="index.php?logout">Logout</a>';
} else {
	?>
	<h3>Login</h3>
	<form method="post" action="index.php">
		<input type="text" placeholder="username" name="username"><br>
		<input type="password" placeholder="password" name="password"><br><br>
		<input type="submit" name="login" value="Log In">
	</form>
	<h3>Register</h3>
	<form method="post" action="index.php">
		<input type="text" placeholder="username" name="username"><br>
		<input type="password" placeholder="password" name="password"><br>
		<input type="password" placeholder="password again" name="password_repeat"><br><br>
		<input type="submit" name="register" value="Register">
	</form>
	<?php
}