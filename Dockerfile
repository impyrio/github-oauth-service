#
# Dockerfile for GitHub OAuth proxy server
#
FROM node:9.11.1-alpine
LABEL author="Patrick Kohler"

# Set source directory
RUN mkdir -p /app
WORKDIR /app

# Install dependencies
COPY ["package.json", "package-lock.json", "./"]
RUN npm install \
 && npm cache clean --force \
 && mv /app/node_modules /node_modules

# Copy app source
COPY app.js .

ENV PORT 8000
EXPOSE 8000

CMD [ "npm", "start" ]