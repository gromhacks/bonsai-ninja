<?php
// Pipeline — exercises PHP's idiomatic flow constructs: closures /
// arrow fns, generators (yield), match expressions, array_map /
// array_filter / array_reduce, try / catch / finally, traits,
// null-coalescing, variadic arguments, splat.
require_once __DIR__ . '/storage.php';
use Storage as Store;

trait Loggable {
    protected function audit(string $_s): void {}
}

class Pipeline {
    use Loggable;

    // Generator — yields every tainted token for the caller's foreach.
    public static function tokenize(string $cmd) {
        foreach (explode(' ', $cmd) as $part) {
            if ($part !== '') {
                yield $part;
            }
        }
    }

    // Closure factory — returns an arrow-fn reducer.
    public static function make_joiner(string $sep): \Closure {
        $fallback = function (string $acc, string $tok): string {
            return $acc === '' ? $tok : $acc . ' ' . $tok;
        };
        return fn(string $acc, string $tok): string => $acc === '' ? $fallback($acc, $tok) : "{$acc}{$sep}{$tok}";
    }

    public static function orchestrate(array $envelope): string {
        // Destructuring via list().
        ['cmd' => $cmd, 'user' => $user] = $envelope;
        list($cmdAlias) = [$cmd];
        $cmd = $cmdAlias;

        // Collect tainted tokens from the generator.
        $tokens = [];
        foreach (self::tokenize($cmd) as $t) {
            $tokens[] = $t;
        }

        // Array pipeline with closures + arrow fns.
        $joined = array_reduce(
            array_filter(
                array_map(fn(string $s): string => trim($s), $tokens),
                fn(string $s): bool => $s !== '',
            ),
            self::make_joiner(' '),
            '',
        );

        // match expression routing.
        $routed = match ($envelope['kind']) {
            'run' => "{$joined}",
            'eval' => trim($joined),
            default => $joined,
        };

        // try / catch / finally — taint survives every branch.
        try {
            if ($routed === '') throw new \RuntimeException('empty');
            $valid = [...$envelope, 'cmd' => $routed, 'user' => $user];
        } catch (\Throwable $_e) {
            $valid = [...$envelope, 'cmd' => $routed ?? '', 'user' => $user];
        } finally {
            // no-op — present so the adapter sees the finally clause.
        }

        return Store::persist($valid);
    }
}
