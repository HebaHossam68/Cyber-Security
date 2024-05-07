using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographic_Technique<string, string>
    {
        public string Decrypt(string cipherText, string key)
        {
            char[,] x ={{'a','b','c','d','e'},
            {'f','g','h','i','k'},
            {'l','m','n','o','p'},
            {'q','r','s','t','u'},
            {'v','w','x','y','z'}};


            key = key.ToLower(); 
            char[] charArray = key.ToCharArray();

            for (int i = 0; i < charArray.Length; i++)
            {
                if (charArray[i] == 'j')
                {
                    charArray[i] = 'i';
                }
            }
            key = new string(charArray);

            cipherText = cipherText.ToLower(); 
            charArray = cipherText.ToCharArray();

            for (int i = 0; i < charArray.Length; i++)
            {
                if (charArray[i] == 'j')
                {
                    charArray[i] = 'i';
                }
            }
            cipherText = new string(charArray);

            int k = 0;
            char[,] array2D = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                if (k >= key.Length)
                    break;


                for (int j = 0; j < 5; j++)
                {
                    if (k >= key.Length)
                        break;

                    if (array2D[i, j] == key[k])
                    {
                        k++;
                        i = -1;
                        j = -1;
                        break;
                    }
                    if (k < key.Length && array2D[i, j] == '\0')
                    {
                        array2D[i, j] = key[k];
                        k++;
                        i = -1;
                        j = -1;
                        break;
                    }
                }

            }
            for (int a = 0; a < 5; a++)
            {
                for (int b = 0; b < 5; b++)
                {
                    bool found = false;

                    
                    for (int i = 0; i < 5; i++)
                    {
                        for (int j = 0; j < 5; j++)
                        {
                            if (x[a, b] == array2D[i, j])
                            {
                                found = true;
                                break;
                            }
                        }
                        if (found) break;
                    }

                   
                    if (!found)
                    {
                        for (int i = 0; i < 5; i++)
                        {
                            for (int j = 0; j < 5; j++)
                            {
                                if (array2D[i, j] == '\0')
                                {
                                    array2D[i, j] = x[a, b];
                                    found = true;
                                    break;
                                }
                            }
                            if (found) break;
                        }
                    }
                }
            }
            List<string> list = new List<string>();
            

            for (int i = 0; i < cipherText.Length; i += 2)
            {
                list.Add(cipherText[i].ToString() + cipherText[i + 1]);
            }

            char[,] array = new char[list.Count, 2];

            for (int i = 0; i < list.Count; i++)
            {
                array[i, 0] = list[i][0];

                array[i, 1] = list[i][1];
            }

            for (int i = 0; i < list.Count; i++)
            {

                int i1 = -1, j1 = -1, i2 = -1, j2 = -1;

                for (int xIndex = 0; xIndex < 5; xIndex++)
                {
                    for (int yIndex = 0; yIndex < 5; yIndex++)
                    {
                        if (array2D[xIndex, yIndex] == array[i, 0])
                        {
                            i1 = xIndex;
                            j1 = yIndex;
                        }
                        if (array2D[xIndex, yIndex] == array[i, 1])
                        {
                            i2 = xIndex;
                            j2 = yIndex;
                        }
                        if (i1 != -1 && i2 != -1) 
                            break;

                    }

                    if (i1 != -1 && i2 != -1) 
                        break;
                }


                
                if (i1 == i2)
                {
                    if (j1 - 1 == -1)
                    {
                        j1 = 4;
                    }
                    else
                    {
                        j1 = j1 - 1;
                    }
                    if (j2 - 1 == -1)
                    {
                        j2 = 4;
                    }
                    else
                    {
                        j2 = j2 - 1;
                    }
                    array[i, 0] = array2D[i1, (j1)];
                    array[i, 1] = array2D[i2, (j2)];
                }
                
                else if (j1 == j2)
                {
                    if (i1 - 1 == -1)
                    {
                        i1 = 4;
                    }
                    else
                    {
                        i1 = i1 - 1;
                    }
                    if (i2 - 1 == -1)
                    {
                        i2 = 4;
                    }
                    else
                    {
                        i2 = i2 - 1;
                    }
                    array[i, 0] = array2D[i1, j1];
                    array[i, 1] = array2D[i2, j2];
                }

                else
                {

                    array[i, 0] = array2D[i1, j2];
                    array[i, 1] = array2D[i2, j1];

                }
            }

            string result = "";


            for (int i = 0; i < list.Count; i++)
            {
                
                if ((char)array[i, 1] == 'x' && i == list.Count - 1)
                {
                    result += (char)array[i, 0];
                }
                else
                {
                    result += (char)array[i, 0] + "" + (char)array[i, 1];
                }
            }

            StringBuilder finalResult = new StringBuilder(result);

            for (int i = 1; i < finalResult.Length; i = i + 2)
            {
                if (finalResult[i] == 'x')
                {
                    if (finalResult[i + 1] == finalResult[i - 1])
                    {
                        finalResult.Remove(i, 1);
                        i = i + 1;
                    }
                }
            }
            result = finalResult.ToString();

            return (result);
        }

        public string Encrypt(string plainText, string key)
        {
            char[,] x ={{'a','b','c','d','e'},
            {'f','g','h','i','k'},
            {'l','m','n','o','p'},
            {'q','r','s','t','u'},
            {'v','w','x','y','z'}};


            key = key.ToLower();
            char[] charArray = key.ToCharArray();

            for (int i = 0; i < charArray.Length; i++)
            {
                if (charArray[i] == 'j')
                {
                    charArray[i] = 'i';
                }
            }
            key = new string(charArray);

            plainText = plainText.ToLower(); 
            charArray = plainText.ToCharArray();

            for (int i = 0; i < charArray.Length; i++)
            {
                if (charArray[i] == 'j')
                {
                    charArray[i] = 'i';
                }
            }
            plainText = new string(charArray);

            int k = 0;
            char[,] array2D = new char[5, 5];
            for (int i = 0; i < 5; i++)
            {
                if (k >= key.Length)
                    break;


                for (int j = 0; j < 5; j++)
                {
                    if (k >= key.Length)
                        break;

                    if (array2D[i, j] == key[k])
                    {
                        k++;
                        i = -1;
                        j = -1;
                        break;
                    }
                    if (k < key.Length && array2D[i, j] == '\0')
                    {
                        array2D[i, j] = key[k];
                        k++;
                        i = -1;
                        j = -1;
                        break;
                    }
                }

            }
            for (int a = 0; a < 5; a++)
            {
                for (int b = 0; b < 5; b++)
                {
                    bool found = false;

                    
                    for (int i = 0; i < 5; i++)
                    {
                        for (int j = 0; j < 5; j++)
                        {
                            if (x[a, b] == array2D[i, j])
                            {
                                found = true;
                                break;
                            }
                        }
                        if (found) break;
                    }

                    
                    if (!found)
                    {
                        for (int i = 0; i < 5; i++)
                        {
                            for (int j = 0; j < 5; j++)
                            {
                                if (array2D[i, j] == '\0')
                                {
                                    array2D[i, j] = x[a, b];
                                    found = true;
                                    break;
                                }
                            }
                            if (found) break;
                        }
                    }
                }
            }


            for (int i = 0; i < 5; i++)
            {
                for (int j = 0; j < 5; j++)
                {
                    Console.Write(array2D[i, j] + " ");
                }
                Console.WriteLine();
            }

            List<string> list = new List<string>();

            for (int i = 0; i < plainText.Length; i++)
            {
                if ((i + 1) < plainText.Length && plainText[i] != plainText[i + 1])
                {
                    list.Add(plainText[i].ToString() + plainText[i + 1]);
                    i++;
                }
                else if ((i + 1) < plainText.Length && plainText[i] == plainText[i + 1])
                {
                    list.Add(plainText[i].ToString() + "x");
                }
                else if (i == plainText.Length - 1)
                {
                    list.Add(plainText[i].ToString() + "x");
                }
            }
            char[,] array = new char[list.Count, 2];

            for (int i = 0; i < list.Count; i++)
            {
                array[i, 0] = list[i][0];
                array[i, 1] = list[i][1];
            }

            for (int i = 0; i < list.Count; i++)
            {
                int i1 = -1, j1 = -1, i2 = -1, j2 = -1;

                for (int xIndex = 0; xIndex < 5; xIndex++)
                {
                    for (int yIndex = 0; yIndex < 5; yIndex++)
                    {
                        if (array2D[xIndex, yIndex] == array[i, 0])
                        {
                            i1 = xIndex;
                            j1 = yIndex;
                        }
                        else if (array2D[xIndex, yIndex] == array[i, 1])
                        {

                            i2 = xIndex;
                            j2 = yIndex;
                        }
                    }
                }

                if (i1 == i2)
                {
                    array[i, 0] = array2D[i1, (j1 + 1) % 5];
                    array[i, 1] = array2D[i1, (j2 + 1) % 5];
                }
                else if (j1 == j2)
                {
                    array[i, 0] = array2D[(i1 + 1) % 5, j1];
                    array[i, 1] = array2D[(i2 + 1) % 5, j2];
                }
                else
                {
                    int z = j1;
                    while (z != j2)
                    {
                        z = (z + 1) % 5;
                        if (z == j2)
                        {
                            array[i, 0] = array2D[i1, z];
                            break;
                        }
                    }
                    z = j2;
                    while (z != j1)
                    {
                        z = (z + 1) % 5;
                        if (z == j1)
                        {
                            array[i, 1] = array2D[i2, z];
                            break;
                        }
                    }
                }
            }
            string result = "";

            for (int i = 0; i < list.Count; i++)
            {
                Console.WriteLine(array[i, 0] + " " + array[i, 1]);

                result += (char)array[i, 0] + "" + (char)array[i, 1]; 
            }
            return result;
        }
    }
}