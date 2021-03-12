FROM node:10

# User
RUN groupadd --gid 5000 portal \
    && useradd --home-dir /home/portal --create-home --uid 5000 \
        --gid 5000 --shell /bin/sh --skel /dev/null portal
COPY . /home/portal
USER portal
WORKDIR /home/portal

# npm
RUN npm install

# Start
EXPOSE 7000
CMD [ "npm", "start" ]
