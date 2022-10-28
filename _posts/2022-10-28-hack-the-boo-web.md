---
layout: post
title: "Hack The Boo 2022 - web"
categories: ["ctf", "hacktheboo2022"]
---

## Evaluation Deck

> A powerful demon has sent one of his ghost generals into our world to ruin the fun of Halloween. The ghost can only be defeated by luck. Are you lucky enough to draw the right cards to defeat him and save this Halloween?

This challenge was great for a first day, since it reminds that one should explore everything provided by authors of the CTF (source code, etc), understand how something works and how to exploit it, and not only "win a game".

![initial website](/assets/img/HackTheBoo2022/card_init.png)

There was a card minigame on webpage. Clicking a card either healed or damaged the ghost, and killing a ghost showed that you win, but it did not get the flag. Exploring further into source code and with asistance with Burp i found that after clicking the flag, a POST request to /api/get\_health route was send that I could intercept via burp and change its parameters:

![burp1](/assets/img/HackTheBoo2022/card_burp_1.png)

Looking on the python code how the calculation of health was implemented I found vulnerable lines:

```
code = compile(f'result = {int(current_health)} {operator} {int(attack_power)}', '<string>', 'exec')
exec(code, result)
return response(result.get('result'))
```

Exec with fstring without input validation means troubles...

Because variables current\_health and attack\_power are casted to int, the vulnerable was the "operator variable", however I had to prepare a payload that does not crash the python code.

Therefore if I replace operator with '- 1; result="njaroh4x was here"; unipmortant=' the fstring will compile into 'result = current\_health - 1; result="njaroh4x was here"; unimportant=attack\_power', and give us expected return:

![burp2](/assets/img/HackTheBoo2022/card_burp_2.png)

![burp4](/assets/img/HackTheBoo2022/card_burp_4.png)

Then, changing the "njaroh4x was here" into the open("flag.txt") request was enough to get the flag:

![burp3](/assets/img/HackTheBoo2022/card_burp_3.png)

![burp5](/assets/img/HackTheBoo2022/card_burp_5.png)


## Spookifier

> There's a new trend of an application that generates a spooky name for you. Users of that application later discovered that their real names were also magically changed, causing havoc in their life. Could you help bring down this application?


This day served a simple Flask application that printed your name in different formats:

![spookifier1](/assets/img/HackTheBoo2022/spookifier_1.png)

Exploring python code we could find an SSTI vulnerability:

```
from mako.template import Template
# (...)

def generate_render(converted_fonts):
        result = '''
                <tr>
                        <td>{0}</td>
        </tr>

                <tr>
                <td>{1}</td>
        </tr>

                <tr>
                <td>{2}</td>
        </tr>

                <tr>
                <td>{3}</td>
        </tr>

        '''.format(*converted_fonts)

        return Template(result).render()
# (...)
```

Where the "3" was a passed input "as is". 

Since the template library was "mako" which i never used before, i checked the documentation and found that default execution of variables is "${...}". I tested the classic "${ 7\*7 }" and it worked:

![spookifier2](/assets/img/HackTheBoo2022/spookifier_2.png)

Then I tried open('../flag.txt').read():

![spookifier3](/assets/img/HackTheBoo2022/spookifier_3.png)

Lesson learned: never trust user input!

## Horror Feeds

> An unknown entity has taken over every screen worldwide and is broadcasting this haunted feed that introduces paranormal activity to random internet-accessible CCTV devices. Could you take down this streaming service?

Next challenge website was a login/register input field, which after registering an user one could access dashboard:

![horrorfeeds1](/assets/img/HackTheBoo2022/horror_feeds_1.png)

![horrorfeeds2](/assets/img/HackTheBoo2022/horror_feeds_2.png)

So, we have som CCTV cameras with ghosts inside, but where is the flag?

Inspecting the source code I found that flag is only reflected in the dashboard page if we log in as "admin": 

```
[jaro@archhtb web_horror_feeds]$ cat challenge/application/templates/dashboard.html
<!DOCTYPE html>
<html lang="en">
<!-- (...) -->
            \{\% if user == 'admin' \%\}
<!-- (...) -->
                        <td>{{flag}}</td>

```

Trying to register with admin is unsuccessful, since admin already exists. 

Digging deeper in the source code I found JWT token, and thought "It must be vulnerable", since I saw in code that all input fields were protected from SQL Injection by prepared statements, but it turned out it was dead end, since this JWT token generation was actually secure. Then I finally found what i missed before:


```python
def register(username, password):
    exists = query_db('SELECT * FROM users WHERE username = %s', (username,))

    if exists:
        return False

    hashed = generate_password_hash(password)

    query_db(f'INSERT INTO users (username, password) VALUES ("{username}", "{hashed}")')
    mysql.connection.commit()

    return True
```

... the fstring!

Because the password in the database was hashed by bcrypt, i encrypted "password" string in bcrypt, which gave me value "$2b$12$u2aLcMWZFXIPBM7lJ3VLAOIZeRRELbtIDQHvLzyEwHu3UeB/RQkbK". Since registering "admin" returns "User exists already", i tried the following SQL injection:

`test\", \"$2b$12$u2aLcMWZFXIPBM7lJ3VLAOIZeRRELbtIDQHvLzyEwHu3UeB/RQkbK\"); UPDATE users SET password = \"$2b$12$u2aLcMWZFXIPBM7lJ3VLAOIZeRRELbtIDQHvLzyEwHu3UeB/RQkbK\" WHERE username = \"admin\";-- -`

Unfortunately, this yielded no success...

![horrorfeeds3](/assets/img/HackTheBoo2022/horror_feeds_3.png)

After some Googling I found out that sometimes it is impossible to run SQL queries with ";" inside, so i searched if there is a way to update value in one command with insert in mariadb, and it turned out that there is an "ON DUPLICATE KEY UPDATE" keyword in insert statement. To change admin's password to mine, i ran the following SQL injection:

`admin\", \"\$2b\$12\$u2aLcMWZFXIPBM7lJ3VLAOIZeRRELbtIDQHvLzyEwHu3UeB/RQkbK\") ON DUPLICATE KEY UPDATE password='$2b$12$u2aLcMWZFXIPBM7lJ3VLAOIZeRRELbtIDQHvLzyEwHu3UeB/RQkbK'#;-- -`

Which after login allowed me to grab the flag:

![horrorfeeds4](/assets/img/HackTheBoo2022/horror_feeds_4.png)


## Juggling Facts

> An organization seems to possess knowledge of the true nature of pumpkins. Can you find out what they honestly know and uncover this centuries-long secret once and for all?

It wouldn't be good CTF competition designed to improve cybersecurity awareness, if the one of historically most vulnerable web technologies would be missing... Day 4 greeted us with PHP! :)

This day's website showed us some facts about pumpkins:

![facts1](/assets/img/HackTheBoo2022/facts_1.png)

There was also "Secret Facts" button, that after clicking showed message "Secrets can only be accessed by admin"

After inspecting code I found that there is backend database called "facts" that holds html code as one value and the fact type in second one, while the flag is hardcoded there in "secrets" type. Looking how to request for the secrets facts, there was the following php code:

```php
public function getfacts($router)
    {
        $jsondata = json_decode(file_get_contents('php://input'), true);

        if ( empty($jsondata) || !array_key_exists('type', $jsondata))
        {
            return $router->jsonify(['message' => 'Insufficient parameters!']);
        }

        if ($jsondata['type'] === 'secrets' && $_SERVER['REMOTE_ADDR'] !== '127.0.0.1')
        {
            return $router->jsonify(['message' => 'Currently this type can be only accessed through localhost!']);
        }

        switch ($jsondata['type'])
        {
            case 'secrets':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('secrets')
                ]);

            case 'spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('spooky')
                ]);

            case 'not_spooky':
                return $router->jsonify([
                    'facts' => $this->facts->get_facts('not_spooky')
                ]);

            default:
                return $router->jsonify([
                    'message' => 'Invalid type!'
                ]);
        }
```

It looks like the code does not allow for requesting for secrets, or does it? I'm not well skilled in php, but the "===" during secrets comparison was unique to me, so I researched the php documentation and hacktricks webpages.

It turns out that the "===" compares two objects that are identical both in its type and value, but the switch case statement compares objects by the "==" comparison (reference: [PHP docs](https://www.php.net/manual/en/control-structures.switch.php)). In php, there is a "feature" called "type juggling" (which I figured out after solving the CTF that this is the same as the challenge name :) ). You can check more information about it in [PHP docs](https://www.php.net/manual/en/types.comparisons.php) and [HackTricks](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web/php-tricks-esp). In short version, if i say that "type"=true, it bypasses the check `$jsondata['type'] === 'secrets'` and goes into switch case, compares true == 'secrets' and goes into there.

Short dive into Burp repeater and we get the flag:

![facts2](/assets/img/HackTheBoo2022/facts_2.png)

![facts3](/assets/img/HackTheBoo2022/facts_3.png)
