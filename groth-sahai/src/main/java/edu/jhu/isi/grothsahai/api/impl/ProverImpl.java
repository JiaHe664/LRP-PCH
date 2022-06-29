/*
 * Copyright (c) 2016 Gijs Van Laer
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package edu.jhu.isi.grothsahai.api.impl;

import edu.jhu.isi.grothsahai.api.Prover;
import edu.jhu.isi.grothsahai.entities.CommonReferenceString;
import edu.jhu.isi.grothsahai.entities.Matrix;
import edu.jhu.isi.grothsahai.entities.Proof;
import edu.jhu.isi.grothsahai.entities.SingleProof;
import edu.jhu.isi.grothsahai.entities.Statement;
import edu.jhu.isi.grothsahai.entities.StatementAndWitness;
import edu.jhu.isi.grothsahai.entities.Vector;
import edu.jhu.isi.grothsahai.entities.Witness;
import edu.jhu.isi.grothsahai.json.Serializer;
import it.unisa.dia.gas.jpbc.Element;

import java.util.ArrayList;
import java.util.List;
import java.util.stream.Collectors;

public class ProverImpl implements Prover {
    private CommonReferenceString crs;

    public ProverImpl(final String crs) {
        this.crs = Serializer.deserializeCRS(crs);
    }

    public ProverImpl(final CommonReferenceString crs) {
        this.crs = crs;
    }

    public Proof proof(final String statementAndWitness) {
        final StatementAndWitness statementAndWitnessObj = StatementAndWitness.generateFromJson(statementAndWitness, crs);
        return proof(statementAndWitnessObj.getStatement(), statementAndWitnessObj.getWitness());
    }

    public Proof proof(final String statement, final String witness) {
        final List<Statement> statementsObj = Serializer.deserializeStatement(statement, crs);
        final Witness witnessObj = Serializer.deserializeWitness(witness, crs);
        return proof(statementsObj, witnessObj);
    }

    public Proof proof(final List<Statement> statements, final Witness witness) {
        // commit
        long startTime=System.currentTimeMillis();
        final Matrix R = Matrix.random(crs.getZr(), witness.getX().getLength(), 2);
        final Vector c = R != null ? crs.iota(1, witness.getX()).add(R.multiply(crs.getU1())) : null;
        // System.out.println("the size of C: " + RamUsageEstimator.sizeOf(c.getElements()) + " bytes");
        long endTime=System.currentTimeMillis(); 
        System.out.println("the run time of generating commit C/S： "+(endTime-startTime)+"ms");     // get the run time of generating commit C/S

        final Matrix S = Matrix.random(crs.getZr(), witness.getY().getLength(), 2);
        final Vector d = S != null ? crs.iota(2, witness.getY()).add(S.multiply(crs.getU2())) : null;
        // System.out.println("the size of D: " + RamUsageEstimator.sizeOf(d) + " bytes");     

        // prove      
        final ArrayList<SingleProof> proofs = statements.stream().map(statement -> getSingleProof(statement, witness, R, S)).collect(Collectors.toCollection(ArrayList::new));   
        final Proof proof = new Proof(c, d, proofs);

        // random commit
        startTime=System.currentTimeMillis();   
        final Matrix R_hat = Matrix.random(crs.getZr(), witness.getX().getLength(), 2);
        final Vector c_hat = R_hat != null ? c.add(R_hat.multiply(crs.getU1())) : null;
        // System.out.println("the size of C_hat: " + RamUsageEstimator.sizeOf(c_hat) + " bytes");
        endTime=System.currentTimeMillis(); 
        System.out.println("the run time of generating rand commit C_hat/S_hat： "+(endTime-startTime)+"ms");  // get the run time of generating rand commit C_hat/S_hat

        final Matrix S_hat = Matrix.random(crs.getZr(), witness.getY().getLength(), 2);
        final Vector d_hat = S_hat != null ? d.add(S_hat.multiply(crs.getU2())) : null;  
        // System.out.println("the size of D_hat: " + RamUsageEstimator.sizeOf(d_hat) + " bytes");

        // random proof
        startTime=System.currentTimeMillis();  
        final ArrayList<SingleProof> proofs_rand = new ArrayList<SingleProof>();
        for (int i = 0; i < statements.size(); i++) {
            proofs_rand.add(getSingleProof(statements.get(i), R_hat, S_hat, proof.getProofs().get(i), proof));
        }
        final Proof proof_rand = new Proof(c_hat, d_hat, proofs_rand);
        
        return proof;
    }

    public StatementAndWitness createDisjunctionStatements(final List<Statement> satisfiedStatements, final List<Statement> unsatisfiedStatements, final Witness witness) {
        satisfiedStatements.forEach(statement -> {
            if (!statement.getT().isZero()) {
                throw new IllegalStateException("T should be 0 when doing disjunctions");
            }
        });
        unsatisfiedStatements.forEach(statement -> {
            if (!statement.getT().isZero()) {
                throw new IllegalStateException("T should be 0 when doing disjunctions");
            }
        });
        final int satXLength = witness.getX().getLength();
        final int satYLength = witness.getY().getLength();
        final int unXLength = unsatisfiedStatements.get(0).getB().getLength();
        final int unYLength = unsatisfiedStatements.get(0).getA().getLength();
        final int xLength = 2 * unXLength + 2 * satXLength;
        final int yLength = 2 + satYLength + unYLength;

        final List<Statement> newStatement = createOrStatements(satisfiedStatements, unsatisfiedStatements, satXLength, satYLength, unXLength, unYLength, xLength, yLength);
        final Witness newWitness = createOrWitness(witness, unXLength, unYLength);

        return new StatementAndWitness(newStatement, newWitness);
    }

    private List<Statement> createOrStatements(final List<Statement> satisfiedStatements, final List<Statement> unsatisfiedStatements, final int satXLength, final int satYLength, final int unXLength, final int unYLength, final int xLength, final int yLength) {
        final List<Statement> newStatement = new ArrayList<>();
        newStatement.add(getVStatement(xLength, yLength));
        newStatement.addAll(createCheckX0Statement(satXLength, xLength, yLength));
        newStatement.addAll(createCheckX1Statement(satXLength, xLength, yLength, unXLength));
        newStatement.addAll(updateSatisfiedStatements(satisfiedStatements, satXLength, satYLength, unXLength, unYLength));
        newStatement.addAll(updateUnsatisfiedStatements(unsatisfiedStatements, satXLength, satYLength, unXLength, unYLength));
        return newStatement;
    }

    private List<Statement> updateSatisfiedStatements(final List<Statement> statements, final int satXLength, final int satYLength, final int unXLength, final int unYLength) {
        final List<Statement> newStatements = new ArrayList<>();
        for (final Statement statement : statements) {
            final Vector a = new Vector(Vector.getZeroVector(2, crs.getG1()),
                    statement.getA(),
                    Vector.getZeroVector(unYLength, crs.getG1()));
            final Vector b = new Vector(Vector.getZeroVector(satXLength, crs.getG2()),
                    statement.getB(),
                    Vector.getZeroVector(2 * unXLength, crs.getG2()));
            final Matrix gamma = Matrix.zero(crs.getZr(), 2 * unXLength + 2 * satXLength, 2 + satYLength + unYLength);
            for (int i = 0; i < satXLength; i++) {
                for (int j = 0; j < satYLength; j++) {
                    gamma.set(satXLength + i, 2 + j, statement.getGamma().get(i, j));
                }
            }
            final Element t = statement.getT();
            newStatements.add(new Statement(a, b, gamma, t));
        }
        return newStatements;
    }

    private List<Statement> updateUnsatisfiedStatements(final List<Statement> statements, final int satXLength, final int satYLength, final int unXLength, final int unYLength) {
        final List<Statement> newStatements = new ArrayList<>();
        for (final Statement statement : statements) {
            final Vector a = new Vector(Vector.getZeroVector(2 + satYLength, crs.getG1()),
                    statement.getA());
            final Vector b = new Vector(Vector.getZeroVector(2 * satXLength + unXLength, crs.getG2()),
                    statement.getB());
            final Matrix gamma = Matrix.zero(crs.getZr(), 2 * unXLength + 2 * satXLength, 2 + satYLength + unYLength);
            for (int i = 0; i < unXLength; i++) {
                for (int j = 0; j < unYLength; j++) {
                    gamma.set(2 * satXLength + unXLength + i, 2 + satYLength + j, statement.getGamma().get(i, j));
                }
            }
            final Element t = crs.getGT().newZeroElement().getImmutable();
            newStatements.add(new Statement(a, b, gamma, t));
        }
        return newStatements;
    }

    private List<Statement> createCheckX0Statement(final int satXLength, final int xLength, final int yLength) {
        final List<Statement> checkX0Statement = new ArrayList<>();
        for (int i = 0; i < satXLength; i++) {
            checkX0Statement.add(createCheckVariableStatement(xLength, yLength,
                    i, i + satXLength, 0));
        }
        return checkX0Statement;
    }

    private List<Statement> createCheckX1Statement(final int satXLength, final int xLength, final int yLength, final int unXLength) {
        final List<Statement> checkX0Statement = new ArrayList<>();
        for (int i = 0; i < unXLength; i++) {
            checkX0Statement.add(createCheckVariableStatement(xLength, yLength,
                    i + 2 * satXLength, i + unXLength + 2 * satXLength, 1));
        }
        return checkX0Statement;
    }

    private Statement createCheckVariableStatement(final int xLength, final int yLength, final int row1, final int row2, final int colIndex) {
        final Vector a = Vector.getZeroVector(yLength, crs.getG1());
        final Vector b = Vector.getZeroVector(xLength, crs.getG2());
        final Matrix gamma = Matrix.zero(crs.getZr(), xLength, yLength);
        gamma.set(row1, colIndex, crs.getZr().newOneElement().getImmutable());
        gamma.set(row2, colIndex, crs.getZr().newOneElement().getImmutable().negate());
        return new Statement(a, b, gamma, crs.getGT().newZeroElement().getImmutable());
    }

    private Statement getVStatement(final int xLength, final int yLength) {
        final Vector a = Vector.getZeroVector(yLength, crs.getG1());
        a.set(0, crs.getG1().newOneElement().getImmutable());
        a.set(1, crs.getG1().newOneElement().getImmutable());
        return new Statement(a,
                Vector.getZeroVector(xLength, crs.getG2()),
                Matrix.zero(crs.getZr(), xLength, yLength), crs.getGT().newOneElement().getImmutable());
    }

    private Witness createOrWitness(final Witness witness, final int xLength, final int yLength) {
        final Vector x = new Vector(witness.getX(), witness.getX(),
                Vector.getZeroVector(2 * xLength, crs.getG1()));
        final Element[] v = new Element[2];
        v[0] = crs.getG2().newOneElement().getImmutable();
        v[1] = crs.getG2().newZeroElement().getImmutable();
        final Vector y = new Vector(new Vector(v), witness.getY(),
                Vector.getZeroVector(yLength, crs.getG2()));
        return new Witness(x, y);
    }

    private SingleProof getSingleProof(final Statement statement, final Witness witness, final Matrix R, final Matrix S) {
        long startTime=System.currentTimeMillis();  
        final Matrix T = Matrix.random(crs.getZr(), 2, 2);
        Vector pi;
        if (R != null) {
            pi = R.getTranspose().multiply(crs.iota(2, statement.getB()));
            if (statement.getGamma() != null) {
                pi = pi.add(R.getTranspose().multiply(statement.getGamma()).multiply(crs.iota(2, witness.getY())))
                        .add(R.getTranspose().multiply(statement.getGamma()).multiply(S).multiply(crs.getU2()));
            }
        } else {
            pi = Vector.getQuadraticZeroVector(crs.getB2(), crs.getPairing(), 2);
        }
        pi = pi.sub(T.getTranspose().multiply(crs.getU2()));


        Vector theta;
        if (S != null) {
            theta = S.getTranspose().multiply(crs.iota(1, statement.getA()));
            if (statement.getGamma() != null) {
                theta = theta.add(S.getTranspose().multiply(statement.getGamma().getTranspose())
                        .multiply(crs.iota(1, witness.getX())));
            }
        } else {
            theta = Vector.getQuadraticZeroVector(crs.getB1(), crs.getPairing(), 2);
        }
        theta = theta.add(T.multiply(crs.getU1()));

        // System.out.println("the size of pi: " + RamUsageEstimator.sizeOf(pi) + " bytes");
        // System.out.println("the size of theta: " + RamUsageEstimator.sizeOf(theta) + " bytes");

        long endTime=System.currentTimeMillis(); 
        System.out.println("the run time of generating proof： "+(endTime-startTime)+"ms");  // get the run time of generating proof  

        return new SingleProof(pi, theta);
    }

    private SingleProof getSingleProof(final Statement statement,final Matrix R_hat, final Matrix S_hat, final SingleProof singleProof, final Proof proof) {
        long startTime=System.currentTimeMillis(); 
        
        final Matrix T_hat = Matrix.random(crs.getZr(), 2, 2);
        Vector pi_hat;
        if (R_hat != null) {
            pi_hat = R_hat.getTranspose().multiply(crs.iota(2, statement.getB()));
            if (statement.getGamma() != null) {
                pi_hat = pi_hat.add(singleProof.getPi()).add(R_hat.getTranspose().multiply(statement.getGamma()).multiply(proof.getD()))
                        .add(R_hat.getTranspose().multiply(statement.getGamma()).multiply(S_hat).multiply(crs.getU2()));
            }
        } else {
            pi_hat = Vector.getQuadraticZeroVector(crs.getB2(), crs.getPairing(), 2);
        }
        pi_hat = pi_hat.sub(T_hat.getTranspose().multiply(crs.getU2()));

        Vector theta_hat;
        if (S_hat != null) {
            theta_hat = S_hat.getTranspose().multiply(crs.iota(1, statement.getA()));
            if (statement.getGamma() != null) {
                theta_hat = theta_hat.add(singleProof.getTheta()).add(S_hat.getTranspose().multiply(statement.getGamma().getTranspose())
                        .multiply(proof.getC()));
            }
        } else {
            theta_hat = Vector.getQuadraticZeroVector(crs.getB1(), crs.getPairing(), 2);
        }
        theta_hat = theta_hat.add(T_hat.multiply(crs.getU1()));

        // System.out.println("the size of pi_hat: " + RamUsageEstimator.sizeOf(pi_hat) + " bytes");
        // System.out.println("the size of theta_hat: " + RamUsageEstimator.sizeOf(theta_hat) + " bytes");

        long endTime=System.currentTimeMillis(); 
        System.out.println("the run time of generating rand proof： "+(endTime-startTime)+"ms");  // get the run time of generating rand proof  

        return new SingleProof(pi_hat, theta_hat);
    }


}
