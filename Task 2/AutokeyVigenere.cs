using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char[,] matrix = matrixx();
            string result = "";

            for (int i = 0; i < plainText.Length; i++)
            {
                int xIndix = -1;
                int yIndix = -1;


                for (int z = 0; z < 26; z++)
                {
                    if (plainText[i] == matrix[z, 0])
                    {
                        xIndix = z;
                        break;
                    }
                }
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == matrix[xIndix, j])
                    {
                        yIndix = j;
                        break;
                    }
                }
                result += matrix[0, yIndix];
            }
            Console.WriteLine(result);
            string final = "";
            for (int i = 0; i < plainText.Length; i++)
            {

                int size = plainText.Length - i;


                string key = result.Substring(i, size);
                string plain = plainText.Substring(0, size);
                if (key == plain)
                {
                    final = result.Remove(i, size);
                }

            }
            return (final);
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            char[,] matrix = matrixx();
            string result = "";

            for (int i = 0; i < key.Length; i++)
            {
                int xIndix = -1;
                int yIndix = -1;


                for (int z = 0; z < 26; z++)
                {
                    if (key[i] == matrix[z, 0])
                    {
                        xIndix = z;
                        break;
                    }
                }
                for (int j = 0; j < 26; j++)
                {
                    if (cipherText[i] == matrix[xIndix, j])
                    {
                        yIndix = j;
                        break;
                    }
                }
                result += matrix[0, yIndix];
            }
            string keyStream = key;
            string charsToAdd;

            while (keyStream.Length < cipherText.Length)
            {
                int length1 = cipherText.Length;
                int length2 = keyStream.Length;
                int diff = length1 - length2;

                result = result.Remove(0, keyStream.Length - key.Length);

                if (diff > key.Length)
                {
                    charsToAdd = result.Substring(0, key.Length);

                }
                else
                {
                    charsToAdd = result.Substring(0, diff);
                }

                keyStream = keyStream + charsToAdd;

                result = "";
                for (int i = 0; i < keyStream.Length; i++)
                {
                    int xIndix = -1;
                    int yIndix = -1;
                    for (int z = 0; z < 26; z++)
                    {
                        if (keyStream[i] == matrix[z, 0])
                        {
                            xIndix = z;
                            break;
                        }
                    }
                    for (int j = 0; j < 26; j++)
                    {
                        if (cipherText[i] == matrix[xIndix, j])
                        {
                            yIndix = j;
                            break;
                        }
                    }
                    result += matrix[0, yIndix];
                }
            }

            return (result);
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();
            char[,] matrix = matrixx();
            string result = "";
            int diff = (plainText.Length) - (key.Length);
            string sub = plainText.Substring(0, diff);
            string keyStem = key + sub;

            int xindix = -1;
            int yindix = -1;
            for (int i = 0; i < plainText.Length; i++)
            {

                for (int j = 0; j < 26; j++)
                {
                    if (plainText[i] == matrix[j, 0])
                    {
                        xindix = j;

                    }
                    if (keyStem[i] == matrix[0, j])
                    {
                        yindix = j;
                    }
                    if (xindix != -1 && yindix != -1)
                    {
                        result += matrix[xindix, yindix];
                        xindix = -1;
                        yindix = -1;
                        break;
                    }
                }
            }
            return (result);
        }

        static char[,] matrixx()
        {
            char[,] matrix = new char[26, 26];

            for (int i = 0; i < 26; i++)
            {
                for (int j = 0; j < 26; j++)
                {
                    matrix[i, j] = shiftChar((char)('a' + j), i);
                }
            }

            return matrix;
        }

        static char shiftChar(char character, int shift)
        {
            int index = (character - 'a' + shift) % 26;
            //   if (index < 0)
            // {
            //   index += 26;
            //}
            return (char)('a' + index);
        }

    }
}
