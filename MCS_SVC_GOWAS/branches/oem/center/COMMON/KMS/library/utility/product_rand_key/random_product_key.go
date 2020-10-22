package product_rand_key

import (
  "math/rand"
  "time"
)




// generates a random string of fixed size
func Product_rand_key(size int) (string) {
  var alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
  var seededRand *rand.Rand = rand.New(
                              rand.NewSource(time.Now().UnixNano()))

  buffer := make([]byte, size)
  for i := 0; i < size; i++ {
    buffer[i] = alpha[seededRand.Intn(len(alpha))]
  }

  return string(buffer)
}

