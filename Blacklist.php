<?php
/**
 * Blacklist class to avoid login brute force attacks. SQLite3 required.
 *
 * @version 1.0
 * @author Álvaro Calleja <alvaro.calleja@gmail.com>
 * @link https://github.com/koas/phpLoginBlacklist
 * @license GPL
 * @license http://opensource.org/licenses/gpl-license.php GNU Public License
 *
 * @package Blacklist
 * 
 **/
class Blacklist
{
	/**
	 * Path for the login blacklist db file
	 * @var string 
	 */
	private $dbFile;

	/**
	 * Database instance
	 * @var SQLite3
	 */
	private $db = null;

	/**
	 * E-mail used as identifier for failed attempts
	 * @var string
	 */
	private $email = '';

	// Constants for login attempts status
	const LOGIN_ALLOWED = 0;
	const LOGIN_DENIED  = -1;

	function __construct($dbFile, $email)
	{
		$this->$dbFile = $dbFile;
		$this->email = $email;

		$this->db = new SQLite3($this->$dbFile);
		
		$this->db->exec('CREATE TABLE IF NOT EXISTS blacklist 
						 (email STRING, failedAttempts INTEGER,
						  lastAttempt INTEGER)');
			
		$this->db->exec('CREATE UNIQUE INDEX IF NOT EXISTS email_idx 
						 ON blacklist (email)');
	}

	/**
	 * Returns the number of seconds that a user must wait until next login
	 * attempt based on previous failed attempts
	 * @param  integer $numAttempts Number of previous failed attempts
	 * @return integer              Number of seconds to wait
	 */
	private function getDelay($numAttempts)
	{
		// Any user with more than 10 failed attempts is considered an attacker
		if ($numAttempts < 5)
			return 0;
		else if ($numAttempts < 10)
			return 20;
		else return 86400 * 7; // A week
	}

	/**
	 * Removes the e-mail from the blacklist DB
	 */
	public function remove()
	{
		$query = $this->db->prepare('DELETE FROM blacklist
									 WHERE email = :email');
		$query->bindValue(':email', $this->email, SQLITE3_TEXT);
		$query->execute();
	}

	/**
	 * Returns the number of failed login attempts for a user
	 * @return array       Array with two members: attempts is the number of 
	 *                     failed attempts, lastAttempt is the timestamp (as
	 *                     provided by the time() function) of the last attempt
	 */
	private function getAttempts()
	{
		$query = $this->db->prepare('SELECT failedAttempts, lastAttempt 
									 FROM blacklist
									 WHERE email = :email');
		$query->bindValue(':email', $this->email, SQLITE3_TEXT);
		$queryRes = $query->execute();
		$rows = $queryRes->fetchArray(SQLITE3_ASSOC);

		if (!$rows)
			return ['attempts' => 0, 'lastAttempt' => 0];

		return ['attempts' => $rows['failedAttempts'],
				'lastAttempt' => $rows['lastAttempt']];
	}

	/**
	 * Adds an e-mail to the login blacklist DB or increases the number of 
	 * attempts if already there
	 */
	public function add()
	{
		$attempts = $this->getAttempts()['attempts'] + 1;

		$query = $this->db->prepare('REPLACE INTO blacklist
									 (email, failedAttempts, lastAttempt)
									 VALUES (:email, :attempts, :last)');
		$query->bindValue(':email', $this->email, SQLITE3_TEXT);
		$query->bindValue(':attempts', $attempts, SQLITE3_INTEGER);
		$query->bindValue(':last', time(), SQLITE3_INTEGER);
		$query->execute();
	}

	/**
	 * Checks if a user is allowed to attempt a login. Failed attempts increase
	 * the minimum time between attempts to avoid brute force attacks
	 * @return array         Array with two members: status is a LOGIN_XXX 
	 *                       constant, delay is the number of seconds to wait
	 *                       until next attempt
	 */
	public function canLogin()
	{
		$result = ['status' => self::LOGIN_ALLOWED, 'delay' => 0];

		// Get failed attempts data
		$attData = $this->getAttempts();
		$attempts = $attData['attempts'];
		$lastAttempt = $attData['lastAttempt'];
		
		// Not failed attempts yet, user can try to login
		if ($attempts < 1)
			return $result;

		// If previous failed attempts exist a delay must be applied
		$delay = $this->getDelay($attempts);
		$now = time();

		// Has the delay time passed?
		if ($now - $lastAttempt < $delay)
		{
			// The user still has to wait until next attempt
			$result['status'] = self::LOGIN_DENIED;
			$result['delay'] = $lastAttempt + $delay - $now;
		}

		return $result;
	}
}
