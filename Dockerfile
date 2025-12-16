FROM ubuntu:24.04                                          

RUN apt-get update && apt-get install -y \                 
    build-essential \                                       
    pkg-config \                                             
    libssl-dev \                                       
    libargon2-dev \                                         
    && rm -rf /var/lib/apt/lists/*                           

WORKDIR /app                                                

COPY main.cpp ./                                     

RUN g++ -O2 -std=c++17 -Wall -Wextra -o hasher main.cpp \    
    -lssl -lcrypto -largon2                                 

ENTRYPOINT ["./hasher"]
                      
