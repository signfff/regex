docker build \
  --network=host \
  --build-arg UID=$(id -u) \
  --build-arg GID=$(id -g) \
  -t regex_fuzzing .
docker run \
  --network=host \
  -v /home/lxy/regex_fuzzing:/home/lxy/regex_fuzzing \
  -it \
  --rm \
  regex_fuzzing 
