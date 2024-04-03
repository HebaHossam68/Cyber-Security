using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Web;

namespace SecurityLibrary.AES
{

    public class AES : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            string[,] rc = new string[,] { {"01","02","04","08","10","20","40","80","1b","36"},
                                   {"00","00","00","00","00","00","00","00","00","00" },
                                   {"00","00","00","00","00","00","00","00","00","00" },
                                   {"00","00","00","00","00","00","00","00","00","00" } };
            List<string[,]> keys = new List<string[,]>();
            string[,] inputRc = new string[4, 1];
            string[,] newKey = stringTomatrix(key);
            keys.Add(newKey);
            for (int i = 0; i < 10; i++)
            {
                for (int h = 0; h < 4; h++)
                {
                    inputRc[h, 0] = rc[h, i];
                }
                newKey = GenerateKey(newKey, inputRc);
                keys.Add(newKey);
            }
            string[,] cipherMatrix = stringTomatrix(cipherText);
            cipherMatrix = AddRoundKey(cipherMatrix, keys[10]);
            for (int i = 10; i > 1; i--)
            {
                cipherMatrix = InvShiftRows(cipherMatrix);
                for (int h = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        cipherMatrix[h, j] = InvSBOX(cipherMatrix[h, j]);
                    }
                }
                cipherMatrix = AddRoundKey(cipherMatrix, keys[i - 1]);
                cipherMatrix = InvMixColumn(cipherMatrix);
            }
            cipherMatrix = InvShiftRows(cipherMatrix);
            for (int h = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++)
                {
                    cipherMatrix[h, j] = InvSBOX(cipherMatrix[h, j]);
                }
            }
            cipherMatrix = AddRoundKey(cipherMatrix, keys[0]);
            string plainText = convertMatrixtoString(cipherMatrix);
            plainText = "0x" + plainText;

            return plainText;
        }



        // ------------------------------------------------------ Encrypt --------------------------------------------------------



        public override string Encrypt(string plainText, string key)
        {
            string[,] rc = new string[,] { {"01","02","04","08","10","20","40","80","1b","36"},
                                   {"00","00","00","00","00","00","00","00","00","00" },
                                   {"00","00","00","00","00","00","00","00","00","00" },
                                   {"00","00","00","00","00","00","00","00","00","00" } };
            string[,] inputRc = new string[4, 1];
            string[,] newkey = stringTomatrix(key);
            string[,] plainmatrix = stringTomatrix(plainText);
            plainmatrix = AddRoundKey(plainmatrix, newkey);

            for (int round = 0; round < 9; round++)
            {
                for (int h = 0; h < 4; h++)
                {
                    for (int j = 0; j < 4; j++)
                    {
                        plainmatrix[h, j] = SBOX(plainmatrix[h, j]);
                    }
                    inputRc[h, 0] = rc[h, round];
                }

                // ShiftRows step
                plainmatrix = ShiftRows(plainmatrix);

                // MixColumns step
                plainmatrix = mixcolumn(plainmatrix);

                // Generate new key
                newkey = GenerateKey(newkey, inputRc);

                // AddRoundKey step
                plainmatrix = AddRoundKey(plainmatrix, newkey);
            }

            for (int h = 0; h < 4; h++)
            {
                for (int j = 0; j < 4; j++)
                {
                    plainmatrix[h, j] = SBOX(plainmatrix[h, j]);
                }
                inputRc[h, 0] = rc[h, 9];
            }

            plainmatrix = ShiftRows(plainmatrix);


            newkey = GenerateKey(newkey, inputRc);


            plainmatrix = AddRoundKey(plainmatrix, newkey);

            string cipher = convertMatrixtoString(plainmatrix);
            cipher = "0x" + cipher;
            return cipher;
        }



        // functions
        static public string convertMatrixtoString(string[,] matrix)
        {//fill by col
            string str = "";
            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    str += matrix[i, j];
                }
            }
            return str;
        }

        static string[,] AddRoundKey(string[,] plain, string[,] key)
        {
            string[,] newplain = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    // Convert hexadecimal elements to binary, perform XOR, then convert back to hexadecimal
                    string plainBinary = HexToBinary(plain[i, j]);
                    string keyBinary = HexToBinary(key[i, j]);
                    string xorResultBinary = Xor(plainBinary, keyBinary);
                    newplain[i, j] = binaryToHex(xorResultBinary);
                }
            }
            return newplain;
        }


        static string ShiftLeft(string sub)
        {
            StringBuilder newSub = new StringBuilder();
            string remain = sub.Substring(1);
            newSub.Append(remain).Append("0");

            if (sub[0] == '1')
            {
                newSub = new StringBuilder(Xor(newSub.ToString(), "00011011"));
            }
            return newSub.ToString();
        }


        static string[,] mixcolumn(string[,] arr)
        {
            string[,] r = new string[4, 4];
            string[,] mixarr = new string[,]
            {
                {"2", "3", "1", "1"},
                {"1", "2", "3", "1"},
                {"1", "1", "2", "3"},
                {"3", "1", "1", "2"}
            };

            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    string[] arrxor = new string[4];
                    for (int k = 0; k < 4; k++)
                    {
                        string temp1, temp2;
                        switch (mixarr[i, k])
                        {
                            case "1":
                                arrxor[k] = HexToBinary(arr[k, j]);
                                break;
                            case "2":
                                arrxor[k] = ShiftLeft(HexToBinary(arr[k, j]));
                                break;
                            case "3":
                                temp1 = HexToBinary(arr[k, j]);
                                temp2 = ShiftLeft(HexToBinary(arr[k, j]));
                                arrxor[k] = Xor(temp1, temp2);
                                break;
                        }
                    }

                    string result = arrxor.Aggregate((a, b) => Xor(a, b));

                    r[i, j] = binaryToHex(result);
                }
            }
            return r;
        }


        static string[,] InvMixColumn(string[,] inputArray)
        {
            string[,] invMixArray = new string[,]
            {
                {"14", "11", "13", "9"},
                {"9", "14", "11", "13"},
                {"13", "9", "14", "11"},
                {"11", "13", "9", "14"}
            };

            string[] mixed = new string[4];
            string[,] finalArray = new string[4, 4];

            for (int row = 0; row < 4; row++)
            {
                for (int column = 0; column < 4; column++)
                {
                    for (int k = 0; k < 4; k++)
                    {
                        string binaryValue = HexToBinary(inputArray[k, column]);

                        switch (invMixArray[row, k])
                        {
                            case "9":
                                mixed[k] = Xor(ShiftLeft(ShiftLeft(ShiftLeft(binaryValue))), binaryValue);
                                break;
                            case "11":
                                mixed[k] = Xor(ShiftLeft(Xor(ShiftLeft(ShiftLeft(binaryValue)), binaryValue)), binaryValue);
                                break;
                            case "13":
                                mixed[k] = Xor(ShiftLeft(ShiftLeft(Xor(ShiftLeft(binaryValue), binaryValue))), binaryValue);
                                break;
                            case "14":
                                mixed[k] = ShiftLeft(Xor(ShiftLeft(Xor(ShiftLeft(binaryValue), binaryValue)), binaryValue));
                                break;
                        }
                    }

                    string result = mixed.Aggregate((a, b) => Xor(a, b));

                    finalArray[row, column] = binaryToHex(result);
                }
            }

            return finalArray;
        }

        static string[,] stringTomatrix(string arr)
        {

            int y = 2;
            string[,] a = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    a[j, i] = arr.Substring(y, 2);
                    y += 2;
                }

            }
            return a;
        }

        static string[,] GenerateKey(string[,] key, string[,] rc)
        {
            string[,] newRound = new string[4, 4];
            string[,] column = new string[4, 1];

            for (int i = 0; i < 3; i++)
            {
                column[i, 0] = key[i + 1, 3];
                column[i, 0] = SBOX(column[i, 0]);
            }
            column[3, 0] = key[0, 3];
            column[3, 0] = SBOX(column[3, 0]);

            for (int j = 0; j < 4; j++)
            {
                for (int i = 0; i < 4; i++)
                {
                    if (j == 0)
                    {
                        string c = Xor(HexToBinary(key[i, j]), HexToBinary(column[i, 0])); // Fixed index for column
                        c = Xor(c, HexToBinary(rc[i, j]));
                        newRound[i, j] = binaryToHex(c);
                    }
                    else
                    {
                        string c = Xor(HexToBinary(newRound[i, j - 1]), HexToBinary(key[i, j])); // Use newRound instead of key
                        newRound[i, j] = binaryToHex(c);
                    }
                }
            }
            return newRound;
        }


        static string binaryToHex(string hex)
        {
            string binary = "";

            List<Tuple<string, char>> mappings = new List<Tuple<string, char>>() {
            new Tuple<string, char>("0000", '0'),
            new Tuple<string, char>("0001", '1'),
            new Tuple<string, char>("0010", '2'),
            new Tuple<string, char>("0011", '3'),
            new Tuple<string, char>("0100", '4'),
            new Tuple<string, char>("0101", '5'),
            new Tuple<string, char>("0110", '6'),
            new Tuple<string, char>("0111", '7'),
            new Tuple<string, char>("1000", '8'),
            new Tuple<string, char>("1001", '9'),
            new Tuple<string, char>("1010", 'A'),
            new Tuple<string, char>("1011", 'B'),
            new Tuple<string, char>("1100", 'C'),
            new Tuple<string, char>("1101", 'D'),
            new Tuple<string, char>("1110", 'E'),
            new Tuple<string, char>("1111", 'F')
            };

            for (int i = 0; i < hex.Length; i += 4)
            {
                string result = hex.Substring(i, 4);
                foreach (var mapping in mappings)
                {
                    if (mapping.Item1 == result)
                    {
                        binary += mapping.Item2;
                        break;
                    }
                }
            }
            return binary;
        }


        static string SBOX(string s)
        {
            string[,] sbox = new string[,]
            {
                { "63", "7c", "77", "7b", "f2", "6b", "6f", "c5", "30", "01", "67", "2b", "fe", "d7", "ab", "76" },
                { "ca", "82", "c9", "7d", "fa", "59", "47", "f0", "ad", "d4", "a2", "af", "9c", "a4", "72", "c0" },
                { "b7", "fd", "93", "26", "36", "3f", "f7", "cc", "34", "a5", "e5", "f1", "71", "d8", "31", "15" },
                { "04", "c7", "23", "c3", "18", "96", "05", "9a", "07", "12", "80", "e2", "eb", "27", "b2", "75" },
                { "09", "83", "2c", "1a", "1b", "6e", "5a", "a0", "52", "3b", "d6", "b3", "29", "e3", "2f", "84" },
                { "53", "d1", "00", "ed", "20", "fc", "b1", "5b", "6a", "cb", "be", "39", "4a", "4c", "58", "cf" },
                { "d0", "ef", "aa", "fb", "43", "4d", "33", "85", "45", "f9", "02", "7f", "50", "3c", "9f", "a8" },
                { "51", "a3", "40", "8f", "92", "9d", "38", "f5", "bc", "b6", "da", "21", "10", "ff", "f3", "d2" },
                { "cd", "0c", "13", "ec", "5f", "97", "44", "17", "c4", "a7", "7e", "3d", "64", "5d", "19", "73" },
                { "60", "81", "4f", "dc", "22", "2a", "90", "88", "46", "ee", "b8", "14", "de", "5e", "0b", "db" },
                { "e0", "32", "3a", "0a", "49", "06", "24", "5c", "c2", "d3", "ac", "62", "91", "95", "e4", "79" },
                { "e7", "c8", "37", "6d", "8d", "d5", "4e", "a9", "6c", "56", "f4", "ea", "65", "7a", "ae", "08" },
                { "ba", "78", "25", "2e", "1c", "a6", "b4", "c6", "e8", "dd", "74", "1f", "4b", "bd", "8b", "8a" },
                { "70", "3e", "b5", "66", "48", "03", "f6", "0e", "61", "35", "57", "b9", "86", "c1", "1d", "9e" },
                { "e1", "f8", "98", "11", "69", "d9", "8e", "94", "9b", "1e", "87", "e9", "ce", "55", "28", "df" },
                { "8c", "a1", "89", "0d", "bf", "e6", "42", "68", "41", "99", "2d", "0f", "b0", "54", "bb", "16" }
            };

            s = s.ToUpper();

            int o = int.Parse(s[0].ToString(), System.Globalization.NumberStyles.HexNumber);
            int v = int.Parse(s[1].ToString(), System.Globalization.NumberStyles.HexNumber);

            return sbox[o, v];
        }


        static string InvSBOX(string s)
        {
            string[,] InvSbox ={{ "52", "09", "6a", "d5", "30", "36", "a5", "38", "bf", "40", "a3", "9e", "81", "f3", "d7", "fb" },
                            { "7c", "e3", "39", "82", "9b", "2f", "ff", "87", "34", "8e", "43", "44", "c4", "de", "e9", "cb" },
                            { "54", "7b", "94", "32", "a6", "c2", "23", "3d", "ee", "4c", "95", "0b", "42", "fa", "c3", "4e" },
                            { "08", "2e", "a1", "66", "28", "d9", "24", "b2", "76", "5b", "a2", "49", "6d", "8b", "d1", "25" },
                            { "72", "f8", "f6", "64", "86", "68", "98", "16", "d4", "a4", "5c", "cc", "5d", "65", "b6", "92" },
                            { "6c", "70", "48", "50", "fd", "ed", "b9", "da", "5e", "15", "46", "57", "a7", "8d", "9d", "84" },
                            { "90", "d8", "ab", "00", "8c", "bc", "d3", "0a", "f7", "e4", "58", "05", "b8", "b3", "45", "06" },
                            { "d0", "2c", "1e", "8f", "ca", "3f", "0f", "02", "c1", "af", "bd", "03", "01", "13", "8a", "6b" },
                            { "3a", "91", "11", "41", "4f", "67", "dc", "ea", "97", "f2", "cf", "ce", "f0", "b4", "e6", "73" },
                            { "96", "ac", "74", "22", "e7", "ad", "35", "85", "e2", "f9", "37", "e8", "1c", "75", "df", "6e" },
                            { "47", "f1", "1a", "71", "1d", "29", "c5", "89", "6f", "b7", "62", "0e", "aa", "18", "be", "1b" },
                            { "fc", "56", "3e", "4b", "c6", "d2", "79", "20", "9a", "db", "c0", "fe", "78", "cd", "5a", "f4" },
                            { "1f", "dd", "a8", "33", "88", "07", "c7", "31", "b1", "12", "10", "59", "27", "80", "ec", "5f" },
                            { "60", "51", "7f", "a9", "19", "b5", "4a", "0d", "2d", "e5", "7a", "9f", "93", "c9", "9c", "ef" },
                            { "a0", "e0", "3b", "4d", "ae", "2a", "f5", "b0", "c8", "eb", "bb", "3c", "83", "53", "99", "61" },
                            { "17", "2b", "04", "7e", "ba", "77", "d6", "26", "e1", "69", "14", "63", "55", "21", "0c", "7d" },
        };


            s = s.ToUpper();
            int o = int.Parse(s[0].ToString(), System.Globalization.NumberStyles.HexNumber);
            int v = int.Parse(s[1].ToString(), System.Globalization.NumberStyles.HexNumber);

            return InvSbox[o, v];


        }

        static string HexToBinary(string hex)
        {
            hex = hex.ToUpper();
            string binary = "";

            List<Tuple<char, string>> mappings = new List<Tuple<char, string>>() {
                new Tuple<char, string>('0', "0000"),
                new Tuple<char, string>('1', "0001"),
                new Tuple<char, string>('2', "0010"),
                new Tuple<char, string>('3', "0011"),
                new Tuple<char, string>('4', "0100"),
                new Tuple<char, string>('5', "0101"),
                new Tuple<char, string>('6', "0110"),
                new Tuple<char, string>('7', "0111"),
                new Tuple<char, string>('8', "1000"),
                new Tuple<char, string>('9', "1001"),
                new Tuple<char, string>('A', "1010"),
                new Tuple<char, string>('B', "1011"),
                new Tuple<char, string>('C', "1100"),
                new Tuple<char, string>('D', "1101"),
                new Tuple<char, string>('E', "1110"),
                new Tuple<char, string>('F', "1111")
                };

            for (int i = 0; i < hex.Length; i++)
            {
                foreach (var mapping in mappings)
                {
                    if (mapping.Item1 == hex[i])
                    {
                        binary += mapping.Item2;
                        break;
                    }
                }
            }
            return binary;
        }


        static string Xor(string a, string b)
        {
            string res = "";
            int size = b.Length;
            for (int i = 0; i < size; i++)
            {
                if (a[i] != b[i])
                {
                    res += "1";
                }
                else
                {
                    res += "0";
                }
            }
            return res;
        }

        static string[,] ShiftRows(string[,] arr)
        {
            string[,] shiftedArr = new string[4, 4];
            for (int i = 0; i < 4; i++)
            {
                shiftedArr[0, i] = arr[0, i];
            }

            for (int j = 0; j < 4; j++)
            {
                shiftedArr[1, j] = arr[1, (j + 1) % 4];
            }

            for (int j = 0; j < 4; j++)
            {
                shiftedArr[2, j] = arr[2, (j + 2) % 4];
            }
            for (int j = 0; j < 4; j++)
            {
                shiftedArr[3, j] = arr[3, (j + 3) % 4];
            }
            return shiftedArr;
        }


        static string[,] InvShiftRows(string[,] arr)
        {
            string[,] shiftedArr = new string[4, 4];

            for (int i = 0; i < 4; i++)
            {
                shiftedArr[0, i] = arr[0, i];
            }

            for (int j = 0; j < 4; j++)
            {
                shiftedArr[1, j] = arr[1, (j + 3) % 4];
            }

            for (int j = 0; j < 4; j++)
            {
                shiftedArr[2, j] = arr[2, (j + 2) % 4];
            }

            for (int j = 0; j < 4; j++)
            {
                shiftedArr[3, j] = arr[3, (j + 1) % 4];
            }

            return shiftedArr;
        }



    }
}