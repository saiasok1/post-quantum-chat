import { useState } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Play, RotateCcw } from "lucide-react";
import { cryptoEngine, KemAlgorithm, SignatureAlgorithm } from "@/lib/crypto";
import { BarChart, Bar, XAxis, YAxis, CartesianGrid, Tooltip, ResponsiveContainer, Cell } from "recharts";

interface BenchmarkResult {
    category: "KEM" | "Signature";
    algorithm: string;
    keygenTime: number;
    encapsulateTime?: number; // KEM only
    decapsulateTime?: number; // KEM only
    signTime?: number; // DSA only
    verifyTime?: number; // DSA only
    publicKeySize: number;
}

const KEM_ALGOS: KemAlgorithm[] = [
    "ml-kem-768",
    "kyber-768",
    "ML KemEcdh768",
    "ML KemEcdh1024",
    "rsa-2048",
    "ecdh-p256"
];

const SIG_ALGOS: SignatureAlgorithm[] = [
    "ml-dsa-65",
    "rsa-pss-2048",
    "ecdsa-p256"
];

const COLORS = {
    pq: ["#8884d8", "#83a6ed", "#8dd1e1"], // Purples/Blues for Post-Quantum
    classic: ["#ffc658", "#ff7300", "#ff0000"] // Oranges/Reds for Classical
};

const getAlgorithmColor = (algo: string, index: number) => {
    const isPQ = algo.startsWith("ml-") || algo.startsWith("kyber") || algo.startsWith("ML ");
    if (isPQ) return COLORS.pq[index % COLORS.pq.length];
    return COLORS.classic[index % COLORS.classic.length];
};

export function CryptoBenchmark() {
    const [results, setResults] = useState<BenchmarkResult[]>([]);
    const [isRunning, setIsRunning] = useState(false);

    const runBenchmark = async () => {
        setIsRunning(true);
        setResults([]);
        const newResults: BenchmarkResult[] = [];

        try {
            // 1. Benchmark KEMs
            for (const alg of KEM_ALGOS) {
                console.log(`Testing KEM ${alg}...`);

                // KeyGen
                const t0 = performance.now();
                const keyPair = await cryptoEngine.generateKEMKeyPair(alg);
                const t1 = performance.now();
                const keygenTime = t1 - t0;

                // Encapsulate (using same keypair, "self-encapsulate")
                const t2 = performance.now();
                const { ciphertext } = await cryptoEngine.encapsulate(keyPair.publicKey);
                const t3 = performance.now();
                const encapTime = t3 - t2;

                // Decapsulate self-encapsulated
                // Reset key exchange progress in engine first? 
                // No, calling encapsulate sets `keyExchangeInProgress`. decapsulate expects it or not?
                // Actually `decapsulate` in CryptoEngine throws if `keyExchangeInProgress` is TRUE (from encap).
                // BUT `encapsulate` sets it to false in `finally`. So it's safe.

                const t4 = performance.now();
                await cryptoEngine.decapsulate(ciphertext);
                const t5 = performance.now();
                const decapTime = t5 - t4;

                newResults.push({
                    category: "KEM",
                    algorithm: alg,
                    keygenTime,
                    encapsulateTime: encapTime,
                    decapsulateTime: decapTime,
                    publicKeySize: keyPair.publicKey.length / 2, // Hex char count / 2 = bytes
                });

                setResults([...newResults]);
            }

            // 2. Benchmark Signatures
            for (const alg of SIG_ALGOS) {
                console.log(`Testing Signature ${alg}...`);

                const t0 = performance.now();
                const keyPair = await cryptoEngine.generateDSAKeyPair(alg);
                const t1 = performance.now();
                const keygenTime = t1 - t0;

                const message = "Hello World Benchmark";

                // Sign
                const t2 = performance.now();
                const signature = await cryptoEngine.sign(message);
                const t3 = performance.now();
                const signTime = t3 - t2;

                // Verify
                const t4 = performance.now();
                await cryptoEngine.verify(message, signature, keyPair.publicKey);
                const t5 = performance.now();
                const verifyTime = t5 - t4;

                newResults.push({
                    category: "Signature",
                    algorithm: alg,
                    keygenTime,
                    signTime,
                    verifyTime,
                    publicKeySize: keyPair.publicKey.length / 2
                });

                setResults([...newResults]);
            }

        } catch (error) {
            console.error("Benchmark failed:", error);
        } finally {
            setIsRunning(false);
            cryptoEngine.reset(); // Cleanup
        }
    };

    return (
        <Card className="w-full max-w-4xl mx-auto">
            <CardHeader>
                <div className="flex items-center justify-between">
                    <div>
                        <CardTitle>Algorithm Benchmark</CardTitle>
                        <CardDescription>Compare Classical vs Post-Quantum Algorithms</CardDescription>
                    </div>
                    <div className="gap-2 flex">
                        <Button onClick={runBenchmark} disabled={isRunning} className="gap-2">
                            <Play className="h-4 w-4" />
                            {isRunning ? "Running..." : "Run Tests"}
                        </Button>
                        <Button variant="outline" onClick={() => setResults([])} disabled={isRunning}>
                            <RotateCcw className="h-4 w-4" />
                        </Button>
                    </div>
                </div>
            </CardHeader>
            <CardContent>
                <Table className="mb-8">
                    <TableHeader>
                        <TableRow>
                            <TableHead>Category</TableHead>
                            <TableHead>Algorithm</TableHead>
                            <TableHead>KeyGen (ms)</TableHead>
                            <TableHead>Pub Key (bytes)</TableHead>
                            <TableHead>Op 1 (ms)</TableHead>
                            <TableHead>Op 2 (ms)</TableHead>
                        </TableRow>
                    </TableHeader>
                    <TableBody>
                        {results.length === 0 && (
                            <TableRow>
                                <TableCell colSpan={6} className="text-center h-24 text-muted-foreground">
                                    Click "Run Tests" to begin benchmarking
                                </TableCell>
                            </TableRow>
                        )}
                        {results.map((r, i) => (
                            <TableRow key={i}>
                                <TableCell className="font-medium">{r.category}</TableCell>
                                <TableCell>{r.algorithm}</TableCell>
                                <TableCell>{r.keygenTime.toFixed(2)}</TableCell>
                                <TableCell>{r.publicKeySize}</TableCell>
                                <TableCell>
                                    {r.category === "KEM"
                                        ? `Encap: ${r.encapsulateTime?.toFixed(2)}`
                                        : `Sign: ${r.signTime?.toFixed(2)}`
                                    }
                                </TableCell>
                                <TableCell>
                                    {r.category === "KEM"
                                        ? `Decap: ${r.decapsulateTime?.toFixed(2)}`
                                        : `Verify: ${r.verifyTime?.toFixed(2)}`
                                    }
                                </TableCell>
                            </TableRow>
                        ))}
                    </TableBody>
                </Table>

                {results.length > 0 && (
                    <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                        <Card>
                            <CardHeader>
                                <CardTitle className="text-sm font-medium">Key Generation Time (ms)</CardTitle>
                            </CardHeader>
                            <CardContent className="h-[300px]">
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart data={results} margin={{ top: 20, right: 30, left: 20, bottom: 60 }}>
                                        <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                                        <XAxis
                                            dataKey="algorithm"
                                            angle={-45}
                                            textAnchor="end"
                                            height={60}
                                            interval={0}
                                            tick={{ fill: 'currentColor', fontSize: 12, opacity: 0.8 }}
                                        />
                                        <YAxis tick={{ fill: 'currentColor', fontSize: 12, opacity: 0.8 }} />
                                        <Tooltip
                                            formatter={(value: number) => [`${value.toFixed(2)} ms`, 'Time']}
                                            contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                                        />
                                        <Bar dataKey="keygenTime" radius={[4, 4, 0, 0]}>
                                            {results.map((entry, index) => (
                                                <Cell key={`cell-${index}`} fill={getAlgorithmColor(entry.algorithm, index)} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </CardContent>
                        </Card>

                        <Card>
                            <CardHeader>
                                <CardTitle className="text-sm font-medium">Public Key Size (bytes)</CardTitle>
                            </CardHeader>
                            <CardContent className="h-[300px]">
                                <ResponsiveContainer width="100%" height="100%">
                                    <BarChart data={results} margin={{ top: 20, right: 30, left: 20, bottom: 60 }}>
                                        <CartesianGrid strokeDasharray="3 3" opacity={0.2} />
                                        <XAxis
                                            dataKey="algorithm"
                                            angle={-45}
                                            textAnchor="end"
                                            height={60}
                                            interval={0}
                                            tick={{ fill: 'currentColor', fontSize: 12, opacity: 0.8 }}
                                        />
                                        <YAxis tick={{ fill: 'currentColor', fontSize: 12, opacity: 0.8 }} />
                                        <Tooltip
                                            formatter={(value: number) => [`${value} bytes`, 'Size']}
                                            contentStyle={{ backgroundColor: 'hsl(var(--background))', borderColor: 'hsl(var(--border))' }}
                                        />
                                        <Bar dataKey="publicKeySize" radius={[4, 4, 0, 0]}>
                                            {results.map((entry, index) => (
                                                <Cell key={`cell-${index}`} fill={getAlgorithmColor(entry.algorithm, index)} />
                                            ))}
                                        </Bar>
                                    </BarChart>
                                </ResponsiveContainer>
                            </CardContent>
                        </Card>
                    </div>
                )}
            </CardContent>
        </Card>
    );
}
