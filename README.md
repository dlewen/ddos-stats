Install python requirements:

```
pip install -r requirements.txt
```

Log in to Sightline and create new Sightline user with "system_user" role.

Add API key in cli, replace USERNAME with the user created above (or an already existing user):
```
/ services aaa local apitoken generate USERNAME "DESCRIPTION"
```

Edit config.ini
Update the sightline URL
Add the apitoken from above
Specify the CA cert file (or if you really can't, set ca_verify to False, NOT RECOMMENDED)


Update the local alert database:
```
python3 alertstats.py --update
```

This will take a while the filst time depending on how many alerts you have.

Create monthly report:
```
python3 alertstats.py --monthly 15 -o outfile-monthly.csv
```

Create weekly report
```
python3 alertstats.py --weekly 25 -o outfile-weekly.csv
```
