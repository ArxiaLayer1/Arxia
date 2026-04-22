# Hardware Setup Guide

## Bill of Materials

| Component                    | Approx. Cost |
|------------------------------|-------------|
| TTGO T-Beam v1.1 (ESP32 + SX1276 LoRa + GPS) | $22 |
| 868/915 MHz antenna (SMA)   | $3          |
| 18650 Li-Ion battery         | $4          |
| USB-C cable                  | $2          |
| **Total**                    | **~$31**    |

## Assembly

1. Insert 18650 battery into T-Beam holder (observe polarity)
2. Attach SMA antenna to the LoRa port (not GPS port)
3. Connect USB-C for initial flashing

## Firmware

```bash
cd targets/esp32
cargo build --release --target xtensa-esp32-none-elf
espflash flash --monitor target/xtensa-esp32-none-elf/release/arxia-esp32
```

## Solar Operation

For permanent outdoor nodes:
- 6V / 1W solar panel connected to T-Beam solar input
- Average power consumption: ~80mA at 3.7V (LoRa idle + periodic TX)
- Solar panel provides sufficient charge in 4+ hours of sunlight

## Antenna Considerations

- **Never operate without an antenna** - this can damage the SX1276
- Use a tuned antenna for your frequency band (868 MHz EU / 915 MHz US)
- Higher gain antennas improve range but narrow the radiation pattern
- For omnidirectional coverage: 3 dBi collinear antenna

## LoRa Parameters

Default configuration:
- Bandwidth: 125 kHz
- Spreading Factor: SF7 (adjustable SF7-SF12)
- Coding Rate: 4/5
- TX Power: 14 dBm (EU limit)
