# Interface
### Enumeration
Ports 22 and 80 are open. The webserver is run by Express (node). The home page has a login form and a list of top users, which we grab:

```
melba
autumn
angelita
melody
michel
marcia
maynard
arnold
hollie
emma
```

Looking at the requests made in Burp, we see there is a request to `/api/users`, which has the full list of users, so we grab that also, and set off a `ffuf` command to fuzz `/api`. We find the endpoints `/api/settings` and `/api/backup`, but both are `401`.

The login form makes a POST request to `/login`, sending the data as a JSON payload. The `username` and `password` parameters were not SQL-injectable using `sqlmap`.

I ran `ffuf` with the top 10 users and `rockyou-75.txt`, but no credentials were found. So I tried instead using the full list of unique users and `rockyou-10.txt` (starting with a small file since there were 1922 unique users, and ffuf doesn't have a `-u` option like `hydra`):

```shell-session
$ ffuf -u http://192.168.52.106/login -d '{"username": "FUZZ1", "password": "FUZZ2"}' -H 'Content-Type: application/json' -w /usr/share/seclists/Passwords/Leaked-Databases/rockyou-10.txt:FUZZ2 -w unique_users.txt:FUZZ1 -o login_brute_force.out -fc 401
```

This gave us the credentials: `dev-acct:password`.

We login and then access `/api/settings`, which we found by fuzzing the `/api` endpoint. We see the following:

```json
{"color-theme":"dark","lang":"en","admin":false}
```

I tried to look for a way to manipulate the session cookie but couldn't find anything. Then I noticed that on the home page, when I selected a different theme, a POST request was sent containing:

```json
{"color-theme":"dark"}
```

So I tried sending a request to set `admin` to `true`:

```http
POST /api/settings HTTP/1.1
Host: 192.168.52.106
Content-Length: 37
Accept: application/json, text/plain, */*
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.45 Safari/537.36
Content-Type: application/json
Origin: http://192.168.52.106
Referer: http://192.168.52.106/
Accept-Encoding: gzip, deflate
Accept-Language: en-US,en;q=0.9
Cookie: connect.sid=s%3AVKAOsi6ovSUYMT4ip__bhque-wY2bdgo.%2BdAv0vzR9760adFbnwXGdC4%2B7rZcI%2BRqAAMF4VqKUws
Connection: close

{"color-theme":"dark","admin":true}
```

And it worked. Now we're able to visit `/api/backup`. When we do so, we see a message:

```
Created backup: /var/log/app/logfile-undefined.1647205883257.gz
```

In fact, returning to the homepage, we see a new input form which takes a value and passes it to the backup endpoint as a GET parameter, e.g. `/api/backup?filename=INPUT`. The page then shows an alert saying `Created backup: Created backup: /var/log/app/logfile-INPUT.gz`. So maybe we can get it to put the file in the webroot.

It turns out we can pass `../` at the beginning of the filename to navigate around directories. For example, if we send a request to `/api/backup?filename=/../../../../var/www/logfile`, then we get back `Created backup: /var/www/logfile.gz`. So let's see if we can put this somewhere we can access through the webserver.

I'm going to fuzz the directories at `/var/www/app/FUZZ/` to try to discover the structure of that folder, as files placed in `/var/www/app` are not obviously accessible. We quickly find a `dist` folder, so let's fuzz that now instead. We find `static` and `assets`.

Requesting `/api/backup?filename=/../../../../var/www/app/dist/static/test` and then querying `http://192.168.68.106/test.gz` triggers a file download! After unzipping, we find an empty file.

Fuzzing the backup endpoint for other parameters, we find a `username` parameter. I tried creating a backup using `/api/backup?filename=/../../../../var/www/app/dist/static/FUZZ&username=FUZZ` with the list of unique users and then fuzzing `/FUZZ.gz` with the users wordlist, filtering responses with a size of `29`, but nothing showed up as different (`29` is the size of the `.gz` file containing a `node.log` file that is empty).

### Foothold
If we send a newline character, we can get code execution after. For example, I sent a request to `192.168.60.106/api/backup?filename=%0Aid+>+/var/www/app/dist/static/test.txt%0Atest`. The first newline character (`%0A`) is needed so that everything that follows will be interpreted as a command to be executed. Then we send the command - since this is a blind injection we redirect the output to a file we can read using the webserver. The final newline allows us to control the extension of the file to which we are redirecting command output, since the endpoint appends `.gz` to whatever we provide.

The output of the above command shows we can code execution as the root user.

Using this command injection vulnerability, we get a root shell.