# MySecretNotes

## Sql-injectable flask site

This flask site is a webservice mimmicking a secure note taking software site. You can register a user and write notes, your notes are "hidden" and can only be seen by you. You can share your notes and import other users notes from the public note id. This site is all fine and dandy on the surface, but it is heavily sql injectable. See if you can find all the injection points. I can promise you that you are able to:

* bypass login
* Steal other users passwords
* Steal other users notes
* Write notes on behalf of other users
* and much more...

### Installation

You will need python 3 and flask. To install do: 
```sh 
$ git clone https://github.com/0xlimE/MySecretNotes.git 
$ cd MySecretNotes 
$ sudo apt-get install python3-pip 
$ pip3 install flask backports.pbkdf2
$ python3 app.py 
``` 

The project should run on port 5000 

### Credits

Alessandro Bruni for some flask specific functions.

This site for the template: <https://onepagelove.com/aria>

Emil Kristoffersen for styling notes.html and note.html
