using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.DES
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class DES : CryptographicTechnique
    {

        public override string Decrypt(string cipherText, string key)
        {
            // throw new NotImplementedException();
            int[] Rounds = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int[] initial_permutation = {58,50,42,34,26,18,10,2,
                                        60,52,44,36,28,20,12,4,
                                        62,54,46,38,30,22,14,6,
                                        64,56,48,40,32,24,16,8,
                                        57,49,41,33,25,17,9,1,
                                        59,51,43,35,27,19,11,3,
                                        61,53,45,37,29,21,13,5,
                                        63,55,47,39,31,23,15,7
            };
            int[] expansion_table = {32,1,2,3,4,5,4,5,
                                    6,7,8,9,8,9,10,11,
                                    12,13,12,13,14,15,16,17,
                                    16,17,18,19,20,21,20,21,
                                    22,23,24,25,24,25,26,27,
                                    28,29,28,29,30,31,32,1
            };
            int[] permutation_tab = {16,7,20,21,29,12,28,17,
                                    1,15,23,26,5,18,31,10,
                                    2,8,24,14,32,27,3,9,
                                    19,13,30,6,22,11,4,25
            };
            // The inverse permutation table
            int[] inverse_permutation = {40,8,48,16,56,24,64,32,
                                        39,7,47,15,55,23,63,31,
                                        38,6,46,14,54,22,62,30,
                                        37,5,45,13,53,21,61,29,
                                        36,4,44,12,52,20,60,28,
                                        35,3,43,11,51,19,59,27,
                                        34,2,42,10,50,18,58,26,
                                        33,1,41,9,49,17,57,25
            };
            string binary = HexToBinary(cipherText);
            string keyy = HexToBinary(key);
            string intial_perm = "";
            for (int i = 0; i < 64; i++)
            {
                intial_perm += binary[initial_permutation[i] - 1];
            }
             
            string left = intial_perm.Substring(0, 32);
            string right = intial_perm.Substring(32, 32);
        
            key = ApplyPC_1(keyy);
            string C0 = key.Substring(0, 28);
            string D0 = key.Substring(28);
            string[] EncKeys = new string[16];
            EncKeys = GeneratekeysEnc(C0, D0, 0, Rounds, EncKeys);
            string[] FinalEncKeys = new string[16];
            for (int i = 0; i < EncKeys.Length; i++)
            {
                FinalEncKeys[i] = ApplyPC_2(EncKeys[i]);
            }
            int x = 15;
            int y = 0;
            while (x > y)
            {
                string temp = FinalEncKeys[x];
                FinalEncKeys[x] = FinalEncKeys[y];
                FinalEncKeys[y] = temp;
                x--;
                y++;
            }
            
            for (int q = 0; q < 16; q++)
            {
                string r_expanded = "";
                
                for (int i = 0; i < 48; i++)
                {
                    r_expanded += right[expansion_table[i] - 1];
                }
                string xored = Xor(FinalEncKeys[q], r_expanded);
                string result = sbox(xored);
                string perm = "";
                for (int i = 0; i < 32; i++)
                {
                    perm += result[permutation_tab[i] - 1];
                }
                string xored2 = Xor(perm, left);
                left = xored2;
                if (q < 15)
                {

                    string temp = right;
                    right = xored2;
                    left = temp;
                }

            }
            string r = left + right;
            string plainText = "";
            
            for (int i = 0; i < 64; i++)
            {
                plainText += r[inverse_permutation[i] - 1];
            }
            
            return binaryToHex(plainText);
        }


        public override string Encrypt(string plainText, string key)
        {
            int[] Rounds = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };
            int[] initial_permutation = {58,50,42,34,26,18,10,2,
                                        60,52,44,36,28,20,12,4,
                                        62,54,46,38,30,22,14,6,
                                        64,56,48,40,32,24,16,8,
                                        57,49,41,33,25,17,9,1,
                                        59,51,43,35,27,19,11,3,
                                        61,53,45,37,29,21,13,5,
                                        63,55,47,39,31,23,15,7
            };
            int[] expansion_table = {32,1,2,3,4,5,4,5,
                                    6,7,8,9,8,9,10,11,
                                    12,13,12,13,14,15,16,17,
                                    16,17,18,19,20,21,20,21,
                                    22,23,24,25,24,25,26,27,
                                    28,29,28,29,30,31,32,1
            };
            int[] permutation_tab = {16,7,20,21,29,12,28,17,
                                    1,15,23,26,5,18,31,10,
                                    2,8,24,14,32,27,3,9,
                                    19,13,30,6,22,11,4,25
            };
            
            int[] inverse_permutation = {40,8,48,16,56,24,64,32,
                                        39,7,47,15,55,23,63,31,
                                        38,6,46,14,54,22,62,30,
                                        37,5,45,13,53,21,61,29,
                                        36,4,44,12,52,20,60,28,
                                        35,3,43,11,51,19,59,27,
                                        34,2,42,10,50,18,58,26,
                                        33,1,41,9,49,17,57,25
            };
            string binary = HexToBinary(plainText);
            string keyy = HexToBinary(key);
            string intial_perm = "";
            for (int i = 0; i < 64; i++)
            {
                intial_perm += binary[initial_permutation[i] - 1];
            }
             
            string left = intial_perm.Substring(0, 32);
            string right = intial_perm.Substring(32, 32);
            
            key = ApplyPC_1(keyy);
            string C0 = key.Substring(0, 28);
            string D0 = key.Substring(28);
            string[] EncKeys = new string[16];
            EncKeys = GeneratekeysEnc(C0, D0, 0, Rounds, EncKeys);
            string[] FinalEncKeys = new string[16];
            for (int i = 0; i < EncKeys.Length; i++)
            {
                FinalEncKeys[i] = ApplyPC_2(EncKeys[i]);
            }
            
            for (int q = 0; q < 16; q++)
            {
                string r_expanded = "";
                
                for (int i = 0; i < 48; i++)
                {
                    r_expanded += right[expansion_table[i] - 1];
                }
                string xored = Xor(FinalEncKeys[q], r_expanded);
                string result = sbox(xored);
                string perm = "";
                for (int i = 0; i < 32; i++)
                {
                    perm += result[permutation_tab[i] - 1];
                }
                string xored2 = Xor(perm, left);
                left = xored2;
                if (q < 15)
                {

                    string temp = right;
                    right = xored2;
                    left = temp;
                }

            }
            string r = left + right;
            string ciphertext = "";
            
            for (int i = 0; i < 64; i++)
            {
                ciphertext += r[inverse_permutation[i] - 1];
            }
            
            return binaryToHex(ciphertext);
        }


        string HexToBinary(string hex)
        {
            Dictionary<char, string> Dict = new Dictionary<char, string>() {
        {'0', "0000"}, { '1', "0001" }, { '2', "0010" }, { '3', "0011" },
        { '4', "0100" }, { '5', "0101" }, { '6', "0110" }, { '7', "0111" },
        { '8', "1000" }, { '9', "1001" }, { 'A', "1010" }, { 'B', "1011" },
        { 'C', "1100" }, { 'D', "1101" }, { 'E', "1110" }, { 'F', "1111" }
    };

            
            string binary = "";
            for (int i = 2; i < hex.Length; i++)
            {
                if (Dict.ContainsKey(hex[i]))
                {
                    binary += Dict[hex[i]];
                }
               
            }
            return binary;
        }


        string binaryToHex(string binary)
        {
            StringBuilder hex = new StringBuilder("0x");

            Dictionary<string, char> Dict = new Dictionary<string, char>() {
        {"0000", '0'}, { "0001",'1' }, { "0010",'2' }, { "0011",'3' },
        { "0100",'4' }, { "0101",'5' }, { "0110",'6' }, { "0111",'7' },
        { "1000",'8' }, { "1001",'9' }, { "1010",'A' }, { "1011",'B' },
        { "1100",'C' }, { "1101",'D' }, { "1110",'E' }, { "1111",'F' }
    };

            for (int i = 0; i < binary.Length; i += 4)
            {
                
                string result = binary.Substring(i, Math.Min(4, binary.Length - i)).PadLeft(4, '0');
                hex.Append(Dict[result]);
            }
            return hex.ToString();
        }


        string Xor(string v, string c)
        {
            if (v.Length != c.Length)
            {
                throw new ArgumentException("Inputs must have the same length for XOR operation.");
            }

            StringBuilder XORres = new StringBuilder();

            for (int i = 0; i < v.Length; i++)
            {
                XORres.Append(v[i] != c[i] ? '1' : '0');
            }

            return XORres.ToString();
        }


        string sbox(string xored)
        {

            //Dictionary<char, string> eight_blocks = new Dictionary<char, string>() {

            //{'0', xored.Substring(47,6)}, {'1', xored.Substring(41,6)}, {'2', xored.Substring(35,6)}, {'3', xored.Substring(29,6)},
            //{'4', xored.Substring(23,6)}, {'5', xored.Substring(17,6)}, {'6', xored.Substring(11,6)}, {'7', xored.Substring(5,6)} };

            int[,] s1 = new int[,] {{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7 },
                                    { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8 },
                                    { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0 },
                                    { 15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13 } };

            int[,] s2 = new int[,] {{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10 },
                                    { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5 },
                                    { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15 },
                                    { 13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9 } };

            int[,] s3 = new int[,] {{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8 },
                                    { 13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1 },
                                    { 13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7 },
                                    { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12 } };

            int[,] s4 ={{7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15 },
                        { 13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9 },
                        { 10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4 },
                        { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14} };

            int[,] s5 = new int[,] {{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9 },
                                    { 14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6 },
                                    { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14 },
                                    { 11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3 } };

            int[,] s6 = new int[,] {{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11 },
                                    { 10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8 },
                                    { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6 },
                                    { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13 } };

            int[,] s7 = new int[,] {{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1 },
                                    { 13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6 },
                                    { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2 },
                                    { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12 } };

            int[,] s8 = {{13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7 },
                         { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2 },
                         { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8 },
                         { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11} };

            Dictionary<int, int[,]> eightS = new Dictionary<int, int[,]>()
            {
                {1, s1 }, { 2, s2 }, { 3, s3 }, { 4, s4 },
                { 5, s5 }, { 6, s6 }, { 7, s7 }, { 8, s8 },
            };

            int idx = 0;
            string result = "";

            for (int i = 1; i <= 8; i++)
            {
                string six_bits = xored.Substring(idx, 6);
                idx += 6;

                string row = six_bits.Substring(0, 1) + six_bits.Substring(5, 1);
                string col = six_bits.Substring(1, 4);


                int row_idx = convertBinaryToDecimal(row);
                int col_idx = convertBinaryToDecimal(col);

                int value = eightS[i][row_idx, col_idx];

                result += convertDecimalToBinary(value);

            }
            return result;
        }

        int convertBinaryToDecimal(string binary)
        {
            int result = 0;
            int power = 1; 

            
            for (int i = binary.Length - 1; i >= 0; i--)
            {
                if (binary[i] == '1')
                {
                    result += power; 
                }
                power *= 2; 
            }

            return result;
        }


        string convertDecimalToBinary(int num)
        {
            if (num == 0)
            {
                return "0000"; 
            }

            string result = ""; 

            
            while (num > 0)
            {
                result = (num % 2) + result; 
                num /= 2; 
            }

            
            while (result.Length < 4)
            {
                result = "0" + result;
            }

            return result;
        }


        string ApplyPC_1(string key)
        {
            string s = "";
            int[,] PC_1 = { {57, 49, 41, 33, 25, 17, 9},
                {1, 58, 50, 42, 34, 26, 18},
                {10, 2, 59, 51, 43, 35, 27},
                {19, 11, 3, 60, 52, 44, 36},
                {63, 55, 47, 39, 31, 23, 15},
                {7, 62, 56, 46, 38, 30, 22},
                {14, 6, 61, 53, 45, 37, 29},
                {21, 13, 5, 28, 20, 12, 4} };
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 7; j++)
                {
                    int index = PC_1[i, j];
                    s += key[index - 1];
                }
            }
            return s;
        }

        string ShiftLeft(string sub, int rounds)
        {
            string NewSub = "";
            if (rounds == 1)
            {
                string ToShift = sub.Substring(0, 1);
                string remain = sub.Substring(1);
                NewSub = remain + ToShift;
            }
            else if (rounds == 2)
            {
                string ToShift = sub.Substring(0, 2);
                string remain = sub.Substring(2);
                NewSub = remain + ToShift;
            }
            return NewSub;
        }

        string[] GeneratekeysEnc(string C, string D, int index, int[] Rounds, string[] Keys)
        {
            if (index < 16)
            {
                string NewC = ShiftLeft(C, Rounds[index]);
                string NewD = ShiftLeft(D, Rounds[index]);
                Keys[index] = NewC + NewD;
                index++;
                return GeneratekeysEnc(NewC, NewD, index, Rounds, Keys);
            }
            return Keys;
        }

        string ApplyPC_2(string key)
        {
            string s = "";
            int[,] PC_2 = { { 14, 17, 11, 24, 1, 5 },
                { 3, 28, 15, 6, 21, 10 },
                { 23, 19, 12, 4, 26, 8 },
                { 16, 7, 27, 20, 13, 2 },
                { 41, 52, 31, 37, 47, 55 },
                { 30, 40, 51, 45, 33, 48 },
                { 44, 49, 39, 56, 34, 53 },
                { 46, 42, 50, 36, 29, 32 } };
            for (int i = 0; i < 8; i++)
            {
                for (int j = 0; j < 6; j++)
                {
                    int index = PC_2[i, j];
                    s += key[index - 1];
                }
            }
            return s;
        }
    }
}