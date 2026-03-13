# Wi-Fi Electromagnetic Wave Analyzer

Author: **Ali Derouiche**

This project demonstrates a practical application of **Maxwell's equations** in the analysis and monitoring of Wi-Fi networks.

The program retrieves Wi-Fi parameters from the operating system and connects them to the physics of electromagnetic waves.

It provides:

- Wi-Fi network detection
- Signal strength monitoring
- Security information analysis
- Detection of possible attacks (Evil Twin, jamming)
- Real-time visualization of the electromagnetic wave associated with Wi-Fi frequency

## Scientific Background

Wi-Fi communication is based on electromagnetic waves.  
The electric field of a plane wave can be written as:

E(z,t) = E₀ cos(kz − ωt)

Where:

- k is the wave number
- ω is the angular frequency
- λ is the wavelength
- f is the frequency

Typical Wi-Fi frequencies:

- **2.4 GHz**
- **5 GHz**

From the frequency, the program calculates:

- wavelength
- wave number
- angular frequency

and plots the electromagnetic wave.

## Features

- Real-time Wi-Fi signal analysis
- Electromagnetic wave visualization
- Security indicator
- Network anomaly detection
- Event logging

## Possible Security Alerts

The program can detect:

- Very weak signal (possible **jamming**)
- BSSID change (**Evil Twin attack**)
- Wi-Fi channel modification (possible interference or attack)

## Requirements

Python 3.8+

Install dependencies:

```bash
pip install numpy matplotlib
