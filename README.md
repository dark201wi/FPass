# FPass

FPass is a simple Flipper Zero password manager.

## Using the app

The home screen has three options:

* **Create password** opens a submenu where you can set a label, enter the password, and save the entry.
* **Saved Passwords** opens the labeled list. Select an entry to show its password, type it into a focused field over USB or Bluetooth, change its label, or delete it. **Type password** lets you choose USB or Bluetooth, then shows the connection and typing status. After typing, press **OK** to repeat or retry the input, or **Back** to return. It types only the password; it does not press Enter or submit the form.
* **About** displays the plaintext-storage warning.

Each password is stored as plaintext in its own `password_<id>.txt` file, preceded by `Password: `; labels are stored separately in `labels.txt`. The files persist in the app's data directory. The vault supports up to 20 entries, with labels up to 31 characters and passwords up to 63 characters. Existing combined password files are migrated to individual files when the app starts.

## Security warning

**Passwords are stored in plaintext, not encrypted.** Anyone with access to the Flipper's filesystem or SD card can read them. The app also displays text while it is being entered and when a saved password is opened. For USB, connect the Flipper to your own computer and focus the intended password field before choosing **Type password**. The app reconnects USB in HID mode for each typing action, which can interrupt USB RPC or another active USB service, then restores the previous USB mode. For Bluetooth, select **Bluetooth keyboard**, then pair the host with the advertised **FPass** keyboard and focus the intended field. The BLE keyboard session stays active until FPass closes, allowing repeat/retry without repeatedly restarting the Bluetooth profile. The password is sent as keystrokes and is visible to the connected host. Only printable ASCII characters are supported, using a US keyboard layout. This is a learning prototype, not a secure password manager; do not use it for real or important credentials.

## Building

Build with the Flipper application build tool (`ufbt`) from this directory.
