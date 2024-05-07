using System;
using System.Collections.Generic;
using System.Linq;
using System.Reflection;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RepeatingkeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            cipherText = cipherText.ToLower();
            plainText = plainText.ToLower();
            char[,] matrix = matrixx();
            char[,] matrixx()
            {
                char[,] matri = new char[26, 26];

                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        matri[i, j] = shiftChar((char)('a' + j), i);
                    }
                }

                return matri;
            }

            char shiftChar(char character, int shift)
            {
                int index = (character - 'a' + shift) % 26;
                return (char)('a' + index);
            }


            // --------------------------------------------- Code --------------------------------------------



            StringBuilder resName = new StringBuilder();
            int L = 0;
            int sj = 0, ei = 0;
            while (L < plainText.Length)
            {
                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (matrix[0, j] == plainText[L])
                        {

                            sj = j;
                        }
                        if (matrix[i, sj] == cipherText[L])
                        {

                            ei = i;
                        }
                    }

                }
                resName.Append(matrix[ei, 0]);

                L++;
            }
            int finalKeyIndex = 0;
            string allKey = resName.ToString();
            string originalKey;
            originalKey = allKey.Substring(0, 3);

            int subStringIndex = allKey.IndexOf(originalKey, 1);

            finalKeyIndex = subStringIndex;
            string Key = allKey.Substring(0, finalKeyIndex);
            return Key;

        }


        public string Decrypt(string plan, string key)
        {
            char[,] matrix = matrixx();
            StringBuilder NewKey = new StringBuilder();
            plan = plan.ToLower();
            key = key.ToLower();


            char[,] matrixx()
            {
                char[,] matri = new char[26, 26];

                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        matri[i, j] = shiftChar((char)('a' + j), i);
                    }
                }

                return matri;
            }

            char shiftChar(char character, int shift)
            {
                int index = (character - 'a' + shift) % 26;

                return (char)('a' + index);
            }


            // --------------------------------------------- Code --------------------------------------------

            for (int i = 0; i < plan.Length; i++)
            {
                NewKey.Append(key[i % key.Length]);
            }
            key = NewKey.ToString();

            StringBuilder resName = new StringBuilder();
            int L = 0;
            int sj = 0, ei = 0;
            while (L < plan.Length)
            {
                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (matrix[i, 0] == key[L])
                        {
                            ei = i;
                        }
                        if (matrix[ei, j] == plan[L])
                        {
                            sj = j;
                        }
                    }

                }
                resName.Append(matrix[0, sj]);

                L++;
            }

            return resName.ToString();
        }

        public string Encrypt(string plan, string key)
        {

            char[,] matrix = matrixx();
            StringBuilder NewKey = new StringBuilder();
            plan = plan.ToLower();
            key = key.ToLower();


            char[,] matrixx()
            {
                char[,] matri = new char[26, 26];

                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        matri[i, j] = shiftChar((char)('a' + j), i);
                    }
                }

                return matri;
            }

            char shiftChar(char character, int shift)
            {
                int index = (character - 'a' + shift) % 26;
                //   if (index < 0)
                // {
                //   index += 26;
                //}
                return (char)('a' + index);
            }


            // --------------------------------------------- Code --------------------------------------------

            for (int i = 0; i < plan.Length; i++)
            {
                NewKey.Append(key[i % key.Length]);
            }
            key = NewKey.ToString();

            StringBuilder resName = new StringBuilder();
            int L = 0;
            int sj = 0, ei = 0;
            while (L < plan.Length)
            {
                for (int i = 0; i < 26; i++)
                {
                    for (int j = 0; j < 26; j++)
                    {
                        if (matrix[0, j] == plan[L])
                        {

                            sj = j;
                        }
                        else if (matrix[i, 0] == key[L])
                        {

                            ei = i;
                        }
                    }

                }
                resName.Append(matrix[sj, ei]);

                L++;
            }

            return resName.ToString();

        }
    }
}
