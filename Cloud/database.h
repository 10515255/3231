/* Add the given serial number to our database of
 * issued serial numbers */
int addSerial(int serial);
/* Remove the given serial number from our database
 * of issued serial numbers */
int removeSerial(int targetSerial);

/* Get the balance of the user with the given id
 * from our database of users. */
int getBalance(int targetID);
/* Remove the user with the given id from our 
 * database of users. */
int removeUser(int targetID);
int updateBalance(int userid, int balance);
