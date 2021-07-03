# Python-Open-Weather
## Installation
```
pip install python-open-weather
```
## Using git
```
git clone https://github.com/pmk456/python-open-weather
cd py_open_weather
python setup.py install
```
## Usage
### Get Weather Of a City
```
from weather import Weather
weather = Weather(temperature_unit=None) # Celsius (or) Kelvin (or) Fahrenheit
current_weather = weather.fetch_weather(city='CityName', only_temp=False) # if only_temp is set To True It Will Only return The current temperature in given unit
print(current_weather) # Returns Dictionary with City name, Temperature, Humidity, Pressure, Description
[+] OUTPUT IF TEMPERATURE_UNIT IS NONE
{'City: ': 'Kadiri', 'Temperature In Kelvin: ': '304°K', 'Temperature In Celsius: ': '31°C', 'Temperature In Fahrenheit: ': '88°F', 'Pressure: ': 1008, 'Humidity: ': 42, 'Description: ': 'overcast clouds'}
[+] OUTPUT IF TEMPERATURE UNIT IS SET CELSIUS OR KELVIN OR FAHRENHEIT
{'City: ': 'Kadiri', 'Temperature: ': '{TEMPERATURE IN C OR K OR F}', 'Pressure: ': 1008, 'Humidity: ': 42, 'Description: ': 'overcast clouds'}
[+] OUTPUT IF ONLY_TEMP IS SET TO TRUE
31°C
```
### Get A Table With Temperatures of given city list
```
# Note: This uses prettytable Module So please Install it Using [ pip install prettytable ]
from weather import Weather, celsius
weather = Weather(temperature_unit=celsius)
city = ['Kadiri', 'Hindupur', 'Anantapur', 'Bangalore', 'Kolkata', 'Mumbai']
table = weather.fetch_multiple_city_weather(city)
print(table)
[+] OUTPUT
+-----------------------------------------------------------------+
|                           Weather Data                        |
+-----------+-------------+----------+----------+-----------------+
|    City   | Temperature | Pressure | Humidity |   Description   |
+-----------+-------------+----------+----------+-----------------+
|   Kadiri  |     31°C    |   1008   |    42    | overcast clouds |
|  Hindupur |     29°C    |   1009   |    50    | overcast clouds |
| Anantapur |     32°C    |   1008   |    46    | overcast clouds |
| Bangalore |     26°C    |   941    |    64    |    few clouds   |
|  Kolkata  |     30°C    |   1004   |    89    |       haze      |
|   Mumbai  |     29°C    |   1008   |    84    |       haze      |
+-----------+-------------+----------+----------+-----------------+
```