# Django DRF Challenge
### by Lara Tais

Answer to the challenge provided by email.

## How to get and run the project

You can use virtualenv.

```
mkdir ltais && cd ltais
virtualenv env
source env/bin/activate
git clone https://github.com/lara-tais/ine.git
cd ine
pip install -r requirements.txt
python manage.py test
```

## Some notes on my decisions

### Database:
SQLite for ease of use. In a real world application I would have used PostgreSQL

### Authentication:
For ease of development, I used the built-in Token authentication with a post_save signal and a login endpoint for Token retrieval. 
In a real world system I would have probably used OAuth 2.0 and Token rotation, expiry and renewal. 

### Adaptations:
- Instead of representing the password as *** I made it write-only, so it’s not included in the retrieval serializers.
- I forced groups to lowercase cause it seemed tidier to not have to account for differing capitalizations.

### Thanks for reading!
