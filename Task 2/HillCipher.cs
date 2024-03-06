using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{

    public class HillCipher : ICryptographicTechnique<string, string>, ICryptographicTechnique<List<int>, List<int>>
    {

        public List<int> Analyse(List<int> plainText, List<int> cipherText)
        {

            //throw new NotImplementedException();
            List<int> key = new List<int>();
            int colCount = plainText.Count / 2;
            int[,] cipherMatrix = new int[2, colCount];
            int[,] plainMatrix = new int[2, colCount];
            int count = 0;

            // Convert cipher to matrix 
            for (int j = 0; j < colCount; j++)
            {
                for (int i = 0; i < 2; i++)
                {
                    cipherMatrix[i, j] = cipherText[count];
                    plainMatrix[i, j] = plainText[count];
                    count++;
                }
            }

            // Loop for each column
            for (int col = 0; col < 2; col++)
            {
                int ki = 0;
                int kj = 0;
                bool found = false;

                // Loop until a match is found
                while (ki <= 25 && !found)
                {
                    while (kj <= 25 && !found)
                    {
                        // Check if the key matches for the current column
                        bool match = true;
                        for (int i = 0; i < colCount; i++)
                        {
                            if (((plainMatrix[0, i] * ki) + (plainMatrix[1, i] * kj)) % 26 != cipherMatrix[col, i])
                            {
                                match = false;
                                break;
                            }
                        }

                        if (match)
                        {
                            key.Add(ki);
                            key.Add(kj);
                            found = true;
                        }

                        kj++;
                    }

                    ki++;
                    kj = 0;
                }

                if (!found)
                {
                    throw new InvalidAnlysisException();
                }
            }

            return key;
        }
        public string Analyse(string plainText, string cipherText)
        {
            throw new NotImplementedException();
        }
        public int[,] TransposeMatrix(int[,] matrix)
        {
            int rows = matrix.GetLength(0);
            int cols = matrix.GetLength(1);
            int[,] transposedMatrix = new int[cols, rows];

            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < cols; j++)
                {
                    transposedMatrix[j, i] = matrix[i, j];
                }
            }

            return transposedMatrix;
        }

        public int[,] KeyMatrix(List<int> key)
        {
            int k = key.Count;
            int n = (int)Math.Sqrt(k);
            int[,] matrix = new int[n, n];
            int x = 0;
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < n; j++)
                {
                    matrix[i, j] = key[x] % 26;
                    x++;
                }
            }
            return matrix;
        }
        private int GreatestCommonDivisor(int a, int b)
        {
            
            a = Math.Abs(a);
            b = Math.Abs(b);

            
            while (b != 0)
            {
                int temp = b;
                b = a % b;
                a = temp;
            }

            return a;
        }
        public List<int> matrixMultiplication2(int[,] key, int[,] cipher)
        {
            int n = key.GetLength(0);
            int[,] multiply = new int[n, 1];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < 1; j++)
                {
                    multiply[i, j] = 0;
                    for (int k = 0; k < n; k++)
                    {
                        multiply[i, j] += key[i, k] * cipher[k, j];
                    }
                    multiply[i, j] = multiply[i, j] % 26;
                    if(multiply[i,j]<0)
                    {
                        multiply[i, j] += 26;
                    }
                }
            }
            List<int> plain = new List<int>();
            for (int i = 0; i < n; i++)
            {
                plain.Add(multiply[i, 0]);
            }
            return plain;
        }
        public int multiplicativeInverse(int Det,int mod)
        {
            Det = Det % mod;
            for(int i=1; i<mod;i++)
            {
                if((Det*i)%mod==1)
                {
                    return i;
                }
            }
            return 1;
        }

        public List<int> Decrypt(List<int> cipherText, List<int> key)
        {
            int n = (int)Math.Sqrt(key.Count);
            if (n*n !=key.Count)
            {
                throw new System.Exception();
            }

            foreach (int element in key)
            {
                if (element < 0 || element >= 26)
                {
                    throw new System.Exception("All elements of the key matrix must be nonnegative and less than 26.");
                }
            }

            int[,] keyMatrix = KeyMatrix(key);
            int[,] keyInverse = new int[n, n];
            int determinant;
            int mulInverse;
            int[,] prepared = new int[n, n];
            int padLength = (n - (cipherText.Count % n)) % n;
            List<int> paddedCipherText = new List<int>(cipherText);
            for (int i = 0; i < padLength; i++)
            {
                paddedCipherText.Add(0);
            }

            if (n == 2)
            {
                determinant = (keyMatrix[0, 0] * keyMatrix[1, 1]) - (keyMatrix[1, 0] * keyMatrix[0, 1]);
                if (determinant == 0)
                {
                    throw new System.Exception("Determinant of the key matrix cannot be zero.");
                }
                determinant = (determinant % 26 + 26) % 26;
                if (GreatestCommonDivisor(26, determinant) != 1)
                {
                    throw new ArgumentException("Determinant of the key matrix must be coprime with 26.");
                }
                mulInverse = multiplicativeInverse(determinant, 26);

                prepared[0, 0] = keyMatrix[1, 1];
                prepared[0, 1] = -keyMatrix[0, 1];
                prepared[1, 0] = -keyMatrix[1, 0];
                prepared[1, 1] = keyMatrix[0, 0];

                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        prepared[i, j] = prepared[i, j] % 26;
                        if (prepared[i, j] < 0)
                        {
                            prepared[i, j] += 26;
                        }
                    }
                }

                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        keyInverse[i, j] = (mulInverse * prepared[i, j]) % 26;
                        if (keyInverse[i, j] < 0)
                        {
                            keyInverse[i, j] += 26;
                        }
                    }
                }
            }
            else if (n == 3)
            {
                determinant = keyMatrix[0, 0] * (keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[2, 1] * keyMatrix[1, 2]) -
                              keyMatrix[0, 1] * (keyMatrix[2, 2] * keyMatrix[1, 0] - keyMatrix[1, 2] * keyMatrix[2, 0]) +
                              keyMatrix[0, 2] * (keyMatrix[2, 1] * keyMatrix[1, 0] - keyMatrix[1, 1] * keyMatrix[2, 0]);
                if (determinant == 0)
                {
                    throw new System.Exception("Determinant of the key matrix cannot be zero.");
                }
                determinant = (determinant % 26 + 26) % 26;
                if (GreatestCommonDivisor(26, determinant) != 1)
                {
                    throw new System.Exception("Determinant of the key matrix must be coprime with 26.");
                }
                mulInverse = multiplicativeInverse(determinant, 26);

                prepared[0, 0] = keyMatrix[1, 1] * keyMatrix[2, 2] - keyMatrix[2, 1] * keyMatrix[1, 2];
                prepared[0, 1] = -(keyMatrix[1, 0] * keyMatrix[2, 2] - keyMatrix[2, 0] * keyMatrix[1, 2]);
                prepared[0, 2] = keyMatrix[1, 0] * keyMatrix[2, 1] - keyMatrix[2, 0] * keyMatrix[1, 1];

                prepared[1, 0] = -(keyMatrix[0, 1] * keyMatrix[2, 2] - keyMatrix[2, 1] * keyMatrix[0, 2]);
                prepared[1, 1] = keyMatrix[0, 0] * keyMatrix[2, 2] - keyMatrix[2, 0] * keyMatrix[0, 2];
                prepared[1, 2] = -(keyMatrix[0, 0] * keyMatrix[2, 1] - keyMatrix[2, 0] * keyMatrix[0, 1]);

                prepared[2, 0] = keyMatrix[0, 1] * keyMatrix[1, 2] - keyMatrix[1, 1] * keyMatrix[0, 2];
                prepared[2, 1] = -(keyMatrix[0, 0] * keyMatrix[1, 2] - keyMatrix[1, 0] * keyMatrix[0, 2]);
                prepared[2, 2] = keyMatrix[0, 0] * keyMatrix[1, 1] - keyMatrix[1, 0] * keyMatrix[0, 1];

                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        prepared[i, j] %= 26;
                        if (prepared[i, j] < 0)
                        {
                            prepared[i, j] += 26;
                        }
                    }
                }

                int[,] transposed = TransposeMatrix(prepared);
                for (int i = 0; i < n; i++)
                {
                    for (int j = 0; j < n; j++)
                    {
                        keyInverse[i, j] = (mulInverse * transposed[i, j]) % 26;
                        if (keyInverse[i, j] < 0)
                        {
                            keyInverse[i, j] += 26;
                        }
                    }
                }
            }

            List<int> plain = new List<int>();
            for (int i = 0; i < paddedCipherText.Count; i += n)
            {
                int[,] vector = new int[n, 1];
                for (int j = 0; j < n; j++)
                {
                    vector[j, 0] = paddedCipherText[i + j] % 26;
                }
                List<int> decrypted = matrixMultiplication2(keyInverse, vector);
                plain.AddRange(decrypted);
            }
            return plain;
        }

        public string Decrypt(string cipherText, string key)
        {
            List<int> cipherTextInt = new List<int>();
            foreach (char c in cipherText.ToUpper())
            {
                if (char.IsLetter(c))
                {
                    cipherTextInt.Add((int)(c - 'A'));
                }
            }

            List<int> keyInt = new List<int>();
            foreach (char c in key.ToUpper())
            {
                if (char.IsLetter(c))
                {
                    keyInt.Add((int)(c - 'A'));
                }
            }

            List<int> decryptedInt = Decrypt(cipherTextInt, keyInt);

            StringBuilder decryptedText = new StringBuilder();
            foreach (int num in decryptedInt)
            {
                decryptedText.Append((char)(num + 'A'));
            }

            return decryptedText.ToString().ToLower();
        }



        public List<int> matrixMultiplication(int[,] key, int[,] plain)
        {
            int n = key.GetLength(0);
            int[,] multiply = new int[n, 1];
            for (int i = 0; i < n; i++)
            {
                for (int j = 0; j < 1; j++)
                {
                    multiply[i, j] = 0;
                    for (int k = 0; k < n; k++)
                    {
                        multiply[i, j] += key[i, k] * plain[k, j];
                    }
                    multiply[i, j] = multiply[i, j] % 26;
                }
            }
            List<int> cipher = new List<int>();
            for (int i = 0; i < n; i++)
            {
                cipher.Add(multiply[i, 0]);
            }
            return cipher;
        }

        public List<int> Encrypt(List<int> plainText, List<int> key)
        {
            //throw new NotImplementedException();
            int n = (int)Math.Sqrt(key.Count);
            int padLength = (n - (plainText.Count % n)) % n;
            List<int> paddedPlainText = new List<int>(plainText);
            for (int i = 0; i < padLength; i++)
            {
                paddedPlainText.Add(0);
            }
            int[,] keyMatrix = KeyMatrix(key);
            List<int> cipher = new List<int>();
            for (int i = 0; i < paddedPlainText.Count; i += n)
            {
                int[,] vector = new int[n, 1];
                for (int j = 0; j < n; j++)
                {
                    vector[j, 0] = paddedPlainText[i + j] % 26;
                }
                List<int> encrypted = matrixMultiplication(keyMatrix, vector);
                cipher.AddRange(encrypted);
            }
            return cipher;
        }

        public string Encrypt(string plainText, string key)
        {
            //throw new NotImplementedException();
            List<int> PlainT = new List<int>();
            foreach (char p in plainText)
            {
                if (Char.IsLetter(p))
                {
                    char cc = Char.ToUpper(p);
                    int encrypted = (int)(cc - 'A');
                    PlainT.Add(encrypted);
                }
            }
            List<int> Key = new List<int>();
            foreach (char k in key)
            {
                if (Char.IsLetter(k))
                {
                    char kk = Char.ToUpper(k);
                    int keyEncrypted = (int)(kk - 'A');
                    Key.Add(keyEncrypted);
                }
            }
            List<int> CipherInt = Encrypt(PlainT, Key);
            StringBuilder cipherText = new StringBuilder();
            foreach (int n in CipherInt)
            {
                char c = (char)(n + 'A');
                cipherText.Append(c);
            }
            return cipherText.ToString();
        }

        public List<int> Analyse3By3Key(List<int> plain3, List<int> cipher3)
        {

            //throw new NotImplementedException();
            int[,] pm = new int[3, 3];
            int[,] cm = new int[3, 3];
            int[,] final = new int[3, 3];

            // Fill key matrices
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    pm[i, j] = plain3[i * 3 + j];
                    cm[i, j] = cipher3[i * 3 + j];
                }
            }

            // Calculate determinant of key
            int detofk = pm[0, 0] * (pm[1, 1] * pm[2, 2] - pm[2, 1] * pm[1, 2]) -
                         pm[0, 1] * (pm[1, 0] * pm[2, 2] - pm[1, 2] * pm[2, 0]) +
                         pm[0, 2] * (pm[1, 0] * pm[2, 1] - pm[1, 1] * pm[2, 0]);

            // Ensure positive determinant
            detofk = (detofk % 26 + 26) % 26;

            // Find modular multiplicative inverse
            int b = 0;
            for (int i = 1; i < 26; i++)
            {
                if ((i * detofk) % 26 == 1)
                {
                    b = i;
                    break;
                }
            }

            // Calculate inverse matrix
            int[,] mulmat = new int[3, 3];
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    mulmat[i, j] = ((pm[(j + 1) % 3, (i + 1) % 3] * pm[(j + 2) % 3, (i + 2) % 3]) -
                                    (pm[(j + 1) % 3, (i + 2) % 3] * pm[(j + 2) % 3, (i + 1) % 3])) * b % 26;
                    if (mulmat[i, j] < 0)
                        mulmat[i, j] += 26;
                }
            }

            // Multiply key matrix with cipher matrix
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    for (int k = 0; k < 3; k++)
                    {
                        final[i, j] += mulmat[i, k] * cm[k, j];
                    }
                    final[i, j] %= 26;
                }
            }

            // Flatten and return result
            List<int> plainText = new List<int>();
            for (int i = 0; i < 3; i++)
            {
                for (int j = 0; j < 3; j++)
                {
                    plainText.Add(final[j, i]);
                }
            }
            return plainText;
        }

        public string Analyse3By3Key(string plain3, string cipher3)
        {
            throw new NotImplementedException();
        }



    }
}

