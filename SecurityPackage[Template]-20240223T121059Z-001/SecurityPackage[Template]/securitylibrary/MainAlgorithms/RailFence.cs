using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            int key = 2;

            for (int i = 0; i < plainText.Length / 2; i++)
            {
                if (plainText[i] != cipherText[i])
                {
                    plainText = plainText.Substring(0, i) + plainText.Substring(i + 1);
                    key++;
                }
                if (plainText[i] == cipherText[i])
                {
                    plainText = plainText.Substring(0, i + 1) + plainText.Substring(i + 2);
                }
                if (plainText[0] == cipherText[0] && plainText[1] == cipherText[1])
                {
                    break;
                }
            }
            return key;

        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            cipherText = cipherText.ToLower();
            int column = (int)Math.Ceiling(cipherText.Length / (double)key);
            char[,] pt = new char[key, column];
            int c = 0;
            string plainText = "";

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (c >= cipherText.Length)
                    {
                        break;
                    }
                    pt[i, j] = cipherText[c];
                    c++;
                }


            }

            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    plainText += pt[j, i];

                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            int column = (int)Math.Ceiling(plainText.Length / (double)key);
            char[,] cipher = new char[key, column];
            int c = 0;
            string cipherText = "";

            for (int i = 0; i < column; i++)
            {
                for (int j = 0; j < key; j++)
                {
                    if (c >= plainText.Length)
                    {
                        break;
                    }
                    cipher[j, i] = plainText[c];
                    c++;

                }
            }

            for (int i = 0; i < key; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    cipherText += cipher[i, j];
                }
            }
            return cipherText;
        }
    }
}
