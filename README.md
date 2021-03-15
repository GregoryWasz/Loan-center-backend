# Loan Center Backend

This is a backend for my [loan center react application](https://github.com/GregoryWasz/Loan-center-frontend).

## Python modules:
```commandline
pip install flask
pip install PyJWT
pip install flask_sqlalchemy
```

## If you want to use this better change:


You must set your own database in:
```python
app.config['SQLALCHEMY_DATABASE_URI'] = 'YOUR_DATA_BASE'
```

You should change secret key to generate JWT tokens:
```python
app.config['SECRET_KEY'] = 'YOUR_SECRET_KEY'
```
Both config definitions are in app.py

## Database:
Personnaly I using PostgresSQL. If you want to use this you also need to install:
```commandline
pip install psycopg2
```
