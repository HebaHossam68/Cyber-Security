using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Columnar : ICryptographicTechnique<string, List<int>>
    {
        public List<int> Analyse(string plainText, string cipherText)
        {


            SortedDictionary<int, int> sortedDictionary = new SortedDictionary<int, int>();
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            double plainTxtSize = plainText.Length;

            for (int z = 1; z < Int32.MaxValue; z++)
            {
                int c = 0;
                double width = z;
                double height = Math.Ceiling(plainTxtSize / z); ;
                string[,] pl = new string[(int)height, (int)width];
                for (int i = 0; i < height; i++)
                {
                    for (int j = 0; j < z; j++)
                    {
                        if (c >= plainTxtSize)
                        {
                            pl[i, j] = "";
                        }
                        else
                        {
                            pl[i, j] = plainText[c].ToString();

                            c++;
                        }
                    }
                }
                List<string> mylist = new List<string>();
                for (int i = 0; i < z; i++)
                {
                    string word = "";
                    for (int j = 0; j < height; j++)
                    {
                        word += pl[j, i];
                    }
                    mylist.Add(word);
                }

                if (mylist.Count == 7)
                {
                    string d = "";
                }

                bool correctkey = true;
                string cipherCopy = (string)cipherText.Clone();
                sortedDictionary = new SortedDictionary<int, int>();
                for (int i = 0; i < mylist.Count; i++)
                {
                    //get index of first substring occurance
                    int x = cipherCopy.IndexOf(mylist[i]);
                    if (x == -1)
                    {
                        correctkey = false;
                    }
                    else
                    {
                        sortedDictionary.Add(x, i + 1);
                        cipherCopy.Replace(mylist[i], "#");
                    }

                }
                if (correctkey)
                    break;

            }
            List<int> output = new List<int>();
            Dictionary<int, int> newDictionary = new Dictionary<int, int>();



            for (int i = 0; i < sortedDictionary.Count; i++)
            {
                newDictionary.Add(sortedDictionary.ElementAt(i).Value, i + 1);
            }

            for (int i = 1; i < newDictionary.Count + 1; i++)
            {
                output.Add(newDictionary[i]);
            }
           
            return output;
        }

        public string Decrypt(string cipherText, List<int> key)
        {
            //throw new NotImplementedException();
            string plainText = "";
            int columns = key.Count;
            int rows = (int)Math.Ceiling((double)cipherText.Length / columns);
            cipherText = cipherText.ToLower();
            char[,] pt = new char[rows, columns];
            int a = 0;

            for (int i = 0; i < columns; i++)
            {
                int k = key.IndexOf(i + 1);
                for (int j = 0; j < rows; j++)
                {
                    if (a >= cipherText.Length)
                    {
                        break;
                    }
                    else
                    {
                        pt[j, k] = cipherText[a];
                        a++;
                    }

                }
            }


            for (int i = 0; i < rows; i++)
            {
                for (int j = 0; j < columns; j++)
                {
                    plainText += pt[i, j];
                }
            }
            Console.WriteLine(plainText);

            return plainText;
        }

        public string Encrypt(string plainText, List<int> key)
        {
            //throw new NotImplementedException();
            plainText = plainText.ToLower();
            int column = key.Count;
            int row = (int)Math.Ceiling(plainText.Length / (double)column);
            int c = 0;
            string cipherText = "";
            char[,] cipher = new char[row, column];

            for (int i = 0; i < row; i++)
            {
                for (int j = 0; j < column; j++)
                {
                    if (c >= plainText.Length)
                    {
                        cipher[i, j] = 'X';
                    }
                    else
                    {
                        cipher[i, j] = plainText[c];
                    }
                    c++;
                }
            }

            for (int i = 0; i < column; i++)
            {
                int k = key.IndexOf(i + 1);
                for (int j = 0; j < row; j++)
                {
                    cipherText += cipher[j, k];
                }
            }
            return cipherText;
        }
    }
}
