using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            Dictionary<char, char> alphabet = new Dictionary<char, char>();

            for (int i = 0; i < plainText.Length; i++)
            {
                char plainChar = plainText[i];
                char cipherChar = cipherText[i];

                if (!alphabet.ContainsKey(plainChar))
                {
                    alphabet.Add(plainChar, cipherChar);
                }
            }

            for (char c = 'a'; c <= 'z'; c++)
            {
                if (!alphabet.ContainsKey(c))
                {
                    char availableChar = 'a';
                    while (alphabet.ContainsValue(availableChar))
                    {
                        availableChar++;
                    }
                    alphabet.Add(c, availableChar);
                }
            }

            StringBuilder keyBuilder = new StringBuilder();
            for (char c = 'a'; c <= 'z'; c++)
            {
                keyBuilder.Append(alphabet[c]);
            }

            return keyBuilder.ToString();
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            cipherText = cipherText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < cipherText.Length; i++)
            {
                int index = key.IndexOf(cipherText[i]) + 97;
                plainText += (char)index;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            plainText = plainText.ToLower();
            key = key.ToLower();
            for (int i = 0; i < plainText.Length; i++)
            {
                cipherText += key[plainText[i] - 97];
            }
            return cipherText;
        }







        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	=
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        /// 

        public string AnalyseUsingCharFrequency(string cipher)
        {
            cipher = cipher.ToLower();
            string plainTxt = "";

            Dictionary<char, double> realFreq = new Dictionary<char, double>()
            {
                {'e', 12.51}, {'t', 9.25}, {'a', 8.04}, {'o', 7.60}, {'i', 7.26},
                {'n', 7.09}, {'s', 6.54}, {'r', 6.12}, {'h', 5.49}, {'l', 4.14},
                {'d', 3.99}, {'c', 3.06}, {'u', 2.71}, {'m', 2.53}, {'f', 2.30},
                {'p', 2.00}, {'g', 1.96}, {'w', 1.92}, {'y', 1.73}, {'b', 1.54},
                {'v', 0.99}, {'k', 0.67}, {'x', 0.19}, {'j', 0.16}, {'q', 0.11},
                {'z', 0.09}
            };

            Dictionary<char, double> lettersInCipher = new Dictionary<char, double>();

            for (char i = 'a'; i <= 'z'; i++)
            {
                lettersInCipher.Add(i, 0);
            }

            foreach (char letter in cipher)
            {
                if (lettersInCipher.ContainsKey(letter))
                    lettersInCipher[letter]++;
            }

            int totalLetters = cipher.Length;
            foreach (char letter in lettersInCipher.Keys.ToList())
            {
                lettersInCipher[letter] = (lettersInCipher[letter] / totalLetters) * 100;
            }

            var sortedLettersInCipher = lettersInCipher.OrderByDescending(item => item.Value);

            Dictionary<char, char> letterMapping = new Dictionary<char, char>();
            var sortedRealFreqKeys = realFreq.Keys.ToList();
            var sortedCipherKeys = sortedLettersInCipher.Select(item => item.Key).ToList();
            for (int i = 0; i < sortedCipherKeys.Count; i++)
            {
                letterMapping[sortedCipherKeys[i]] = sortedRealFreqKeys[i];
            }

            foreach (char letter in cipher)
            {
                if (char.IsLetter(letter))
                {
                    plainTxt += letterMapping[letter];
                }
                else
                {
                    plainTxt += letter;
                }
            }

            return plainTxt;
        }
    }
}