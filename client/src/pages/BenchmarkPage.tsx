import { CryptoBenchmark } from "@/components/CryptoBenchmark";
import { Button } from "@/components/ui/button";
import { ArrowLeft } from "lucide-react";
import { Link } from "wouter";

export default function BenchmarkPage() {
    return (
        <div className="min-h-screen bg-background p-6">
            <div className="max-w-4xl mx-auto space-y-6">
                <header className="flex items-center gap-4">
                    <Link href="/">
                        <Button variant="ghost" size="icon">
                            <ArrowLeft className="h-4 w-4" />
                        </Button>
                    </Link>
                    <div className="space-y-1">
                        <h1 className="text-2xl font-bold">Cryptography Benchmark</h1>
                        <p className="text-muted-foreground">
                            Compare performance metrics of Post-Quantum vs Classical algorithms
                        </p>
                    </div>
                </header>

                <CryptoBenchmark />
            </div>
        </div>
    );
}
