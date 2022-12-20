FROM node:10

# User
RUN groupadd --gid 5000 portal \
    && useradd --home-dir /home/portal --create-home --uid 5000 \
        --gid 5000 --shell /bin/sh --skel /dev/null portal
COPY ./package.json /home/portal/package.json
COPY ./package-lock.json /home/portal/package-lock.json

# npm
WORKDIR /home/portal
RUN npm install

COPY . /home/portal
USER portal


# Start
EXPOSE 7000
CMD [ "npm", "start" ]
