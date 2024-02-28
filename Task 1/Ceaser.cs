using System;
using System.Collections.Generic;
using System.Linq;

namespace SecurityLibrary
{
    public class Ceaser : ICryptographicTechnique<string, int>
    {

        public string Encrypt(string plainText, int key)
        {
            //throw new NotImplementedException();
            string cipherText = "";
            foreach (char p in plainText)
            {
                if (Char.IsLetter(p))
                {
                    if (Char.IsUpper(p))
                    {
                        char c = (char)(((p + key - 'A') % 26) + 'A');
                        char cc = Char.ToUpper(c);
                        cipherText += cc;
                    }
                    else if (Char.IsLower(p))
                    {
                        char c = (char)(((p + key - 'a') % 26) + 'a');
                        char cc = Char.ToUpper(c);
                        cipherText += cc;
                    }

                }
                else if (!Char.IsLetter(p))
                {
                    cipherText += p;
                }
            }
            return cipherText;
        }

        public string Decrypt(string cipherText, int key)
        {
            //throw new NotImplementedException();
            String plainText = "";
            foreach (char c in cipherText)
            {
                if (Char.IsLetter(c))
                {
                    if (Char.IsUpper(c))
                    {
                        int number = (c - key - 'A');
                        if (number < 0)
                        {
                            number = number + 26;
                            char pl = (char)((number % 26) + 'A');
                            char pll = Char.ToLower(pl);
                            plainText += pll;
                        }
                        else
                        {
                            char p = (char)(((c - key - 'A') % 26) + 'A');
                            char pp = Char.ToLower(p);
                            plainText += pp;
                        }
                    }
                    else if (Char.IsLower(c))
                    {
                        int number = (c - key - 'a');
                        if (number < 0)
                        {
                            number = number + 26;
                            char pl = (char)((number % 26) + 'a');
                            char pll = Char.ToLower(pl);
                            plainText += pll;
                        }
                        else
                        {
                            char p = (char)(((c - key - 'a') % 26) + 'a');
                            char pp = Char.ToLower(p);
                            plainText += pp;
                        }
                    }
                }
                else if (!Char.IsLetter(c))
                {
                    plainText += c;
                }
            }
            return plainText;
        }

        public int Analyse(string plainText, string cipherText)
        {
            //throw new NotImplementedException();
            string pp = plainText.ToLower();
            string cc = cipherText.ToUpper();
            int key = 0;
            for (int i = 0; i < 26; i++)
            {
                if (Encrypt(pp, i) == cc)
                {
                    key = i;
                    break;
                }
            }
            return key;
        }
    }
}