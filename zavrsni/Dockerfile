FROM python:3.9-slim

LABEL authors="Toni D"

# Set working directory
WORKDIR /

# Copy your Python script and directories into the container
COPY SOCPRO3.py /
COPY "Drugi_napad_logovi" /Drugi_napad_logovi/
COPY "Logovi_za_prikaz" /Logovi_za_prikaz/

# Set the default command to run the script
CMD ["python", "SOCPRO3.py"]