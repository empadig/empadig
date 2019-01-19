
# EmpaDig

EmpaDig is an automated tool for inferring the most important routing events starting from a large amount of traceroutes. Each inferred event is augmented with attributes that include an impact, an estimated time of occurrence, and a set of IP addresses that are likely to be close to the cause of the event.

The algorithm implemented by the tool is described in the scientific paper [*Discovering High-Impact Routing Events using Traceroutes*](http://ieeexplore.ieee.org/document/7405531/).

## Dependencies

- Python v2.7
- PyMongo v2.6.3
- NetworkX v1.8.1 (check this, later versions are incompatible)
- Node.js v0.10.25
- A bunch of Node.js libraries (just type ```npm install``` from the root) 
- MongoDB v2.6.4

What follows assumes that an installation of MongoDB is running on the local machine.

## HowTo

To rerun the experiments of the paper follow the following instructions. 

* Go to the ```scripts/``` directory
* Run ```./start_amsix.sh``` to download data and run computation for experiment 3 of the paper
* Run ```./start_isp.sh``` to download data and run computation for experiment 1 of the paper


EmpaDig scripts execute the following operations:

* Download data from the RIPE Atlas (using the RIPE Atlas API)
* Convert data to a custom format
* Import data in a Mongo Database
* Execute  heuristic to roughly infer load balancers
* Execute empadig algorithm considering the load balancer data
* Execute empadig algorithm without considering the load balancer data
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

## References
* M. Di Bartolomeo, V. Di Donato, M. Pizzonia, C. Squarcella, M. Rimondini. [*Discovering High-Impact Routing Events using Traceroutes*](http://ieeexplore.ieee.org/document/7405531/). Proceedings IEEE Symposium on Computers and Communications (ISCC), Larnaca, Cyprus, Jul. 2015
* D. Ceneda, M. Di Bartolomeo, V. Di Donato, M. Patrignani, M. Pizzonia, M. Rimondini. [*RoutingWatch: Visual Exploration and Analysis of Routing Events*](http://ieeexplore.ieee.org/document/7502863/). Proceedings IEEE/IFIP Network Operations and Management Symposium (NOMS), Istanbul, Turkey, Apr. 2016


## Licenses
* This product includes GeoLite data created by MaxMind, available from [http://www.maxmind.com](http://www.maxmind.com)
* The file algorithm/sortecollection.py, being an [active state](http://code.activestate.com/recipes/577197-sortedcollection/) recipe is under the [MIT License](https://opensource.org/licenses/MIT)
* The rest of the project is under the AGPL-3.0 license

    Empadig
    Copyright (C) 2015 Marco Di Bartolomeo, Valentino Di Donato, Maurizio Pizzonia, Massimo Rimondini, Claudio Squarcella

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
