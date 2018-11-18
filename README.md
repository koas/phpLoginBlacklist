# phpLoginBlacklist
Keeps a list of failed login attempts to prevent brute force attacks.

## Requirements
This class requires the SQLite3 extension to be installed.

## Usage

Follow these steps before the login code section of your app:

1. Create an instance of the class with two parameters: the file path of the sqlite db file (it will be created the first time you use the class) and an email, username or whatever field you use to identify who is trying to login. It is recommended to provide a path _outside_ the web document root (remember to give write permissions on that folder to your web server user).

`$blacklist = new Blacklist('/usr/local/loginBlacklist.db', 'test@test.com');`

2. Call the _canLogin_ method. A hash will be returned with two members: 

* status: Blacklist::LOGIN_ALLOWED means that the user can login, no previous login attempts failed or enough time has passed since the last failed attempt. Blacklist::LOGIN_DENIED means that this user cannot yet login, not enough time has passed since the last failed attempt.
* delay: contains the number of seconds until this user can try to login again, in case you want to inform the user. Will be 0 if _status_ is Blacklist::LOGIN_ALLOWED

3. If the user can login and the login fails, call the _add_ method. This adds that email to the blacklist database or updates its failed attempts counter. If the user successfully logins call the _remove_ method to remove that email from the database.

```
$canLogin = $blacklist->canLogin();
if ($canLogin['status'] == Blacklist::LOGIN_ALLOWED)
{
    // Login code here
    if ($loginSuccessful)
      $blacklist->remove();
    else $blacklist->add();
}
else
{
    echo "Due to security reasons you must wait {$canLogin['delay']} seconds before another login attempt";
}
```

## Delay tuning

You can edit the _getDelay_ method to fine tune the number of seconds to wait between login attempts. By default no delay is needed for less than five attempts, 20 seconds for 5-9 attempts and a week for 10 or more.
