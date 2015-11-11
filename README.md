# EmpaDig

EmpaDig is an automated tool for inferring the most important routing events starting from a large amount of traceroutes. Each inferred event is augmented with attributes that include an impact, an estimated time of occurrence, and a set of IP addresses that are likely to be close to the cause of the event.

## Dependencies

- Python v2.7
  - PyMongo v2.6.3
  - NetworkX v1.8.1
- Node.js v0.10.25
  - A bunch of Node.js libraries (go to ```scripts/``` and type ```npm install```) 
- MongoDB v2.6.4

## HowTo

* Go to the script/ directory
* Edit the file start.sh customizing the following variables:
 
  * start_timestamp=`date -d "2015-03-26 09:30:00" "+%s"`
  * end_timestamp=`date -d "2015-03-28 09:30:00" "+%s"`
  * MSM_ID=1042245
  * db_name="outage"
* ./start.sh

EmpaDig scripts execute the following operations:

* Download data from the RIPE Atlas API
* Convert data to a custom format
* Import data in a Mongo Database
* Execute load balancing heuristic
* Execute empadig algorithm with the load balancing heuristic
* Execute empadig algorithm without the load balancing heuristic
* Generate the associated charts and outputs 

## Output


The algorithm generates the following files:

* events-impact-without-lb-heuristic.png: impact of the inferred events
* events-impact-with-lb-heuristic.png: impact of the inferred events (lb)
* events-impact-without-lb-heuristic-top20.json: properties of the top-20 inferred events
* events-impact-with-lb-heuristic-top20.json: properties of the top-20 inferred events (lb)
* events-without-lb-heuristic.json: inferred events
* events-with-lb-heuristic.json: inferred events (lb)

Of course start.sh can be adapted to download, import and analyze multiple measurements

## Licenses
* This product includes GeoLite data created by MaxMind, available from [http://www.maxmind.com](http://www.maxmind.com)
* The file algorithm/sortecollection.py, being an [active state](http://code.activestate.com/recipes/577197-sortedcollection/) recipe is under the [MIT License](https://opensource.org/licenses/MIT)
* The rest of the project is under the AGPL-3.0 license

    Copyright (C) 2015 Marco Di Bartolomeo, Valentino Di Donato, Maurizio Pizzonia, Claudio Squarcella, Massimo Rimondini

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU Affero General Public License as
    published by the Free Software Foundation, either version 3 of the
    License, or (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Affero General Public License for more details.

    You should have received a copy of the GNU Affero General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.