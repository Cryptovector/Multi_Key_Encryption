import hashlib
import os

def egcd(a, b):
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)

def modinv(a, m):
    g, x, y = egcd(a, m)
    if g != 1:
        raise Exception('modular inverse does not exist')
    else:
        return x % m

def Modulo_Division(a, b, Modulus):
    a = (a + Modulus) % Modulus
    b = (b + Modulus) % Modulus  
    if a == 0:
       return 0     
   
    x = modinv(a, Modulus)
    return ((x * b) % Modulus)

class Gauss_Matrix:
    def __init__(self, length, height, Modulus):
        self.length = length
        self.height = height
        self.Matrix = []
        self.Modulus = Modulus
        self.Per_vec = [i for i in range(length)]

    def Generate_inv_Matrix(self, seed, Groupvector):
        self.Matrix = []
        for i in range(self.length):
            self.Matrix.append([])
            for y in range(self.height):
                Hash = hashlib.sha256()
                Hash.update(i.to_bytes(4, byteorder='big'))
                Hash.update(Groupvector[y].to_bytes(4, byteorder='big'))
                Hash.update(seed)
                self.Matrix[i].append(int.from_bytes(Hash.digest(), byteorder='big')%(self.Modulus-1)+1)    

    def Generate_Matrix(self, seed, Groupvector):
        self.Matrix = []
        for i in range(self.length):
            self.Matrix.append([])
            for y in range(self.height):
                Hash = hashlib.sha256()
                Hash.update(y.to_bytes(4, byteorder='big'))
                Hash.update(Groupvector[i].to_bytes(4, byteorder='big'))
                Hash.update(seed)
                self.Matrix[i].append(int.from_bytes(Hash.digest(), byteorder='big')%(self.Modulus-1)+1)

    def Gaussian_Elimation_Modulo(self):
        n = self.length
        for i in range(n-1, 0, -1): 
            for y in range(i-1, -1, -1):
                if not self.Matrix[i][i]:
                    for z in range(i):
                        if self.Matrix[z][i]:
                            tmp_Matrix = self.Matrix[z]
                            tmp_Per = self.Per_vec[z]
                            self.Matrix[z] = self.Matrix[i]
                            self.Matrix[i] = tmp_Matrix
                            self.Per_vec[z] = self.Per_vec[i]
                            self.Per_vec[i] = tmp_Per
                            break      
                    if not self.Matrix[i][i]:
                        return 0            
                                  
                c = Modulo_Division(self.Matrix[i][i], self.Modulus-self.Matrix[y][i], self.Modulus)
                for z in range(n):
                    self.Matrix[y][z] = (self.Matrix[y][z]+(c*self.Matrix[i][z]))%self.Modulus   
                self.Matrix[y][i] = c
                
                if not self.Matrix[0][0]:
                    return 0                                    

    def Vector_Rec(self, vector):
        n = self.length
        Rec_vec = [0]*n
        End_vec = [0]*n
        for i in range(n-1, -1, -1): 
            c = Modulo_Division(self.Matrix[i][i], self.Modulus-vector[i], self.Modulus) 
            for y in range(i, -1, -1):
                vector[y] = (vector[y]+(c*self.Matrix[i][y]))%self.Modulus
            if c:     
                Rec_vec[i] = self.Modulus-c
            else:
                Rec_vec[i] = 0    
            for y in range(i+1, n):
                Rec_vec[y] += ((self.Modulus-c)*self.Matrix[i][y])
                Rec_vec[y] %= self.Modulus

        for i in range(n):
            End_vec[self.Per_vec[i]] = Rec_vec[i]         

        return End_vec   

    def Vector_Matrix_Multiplication(self, vector):
        New_vector = [0]*self.length

        for i in range(self.height):
            for y in range(self.length):
                New_vector[y] += self.Matrix[y][i]*vector[i]
                New_vector[y] %= self.Modulus

        return New_vector 