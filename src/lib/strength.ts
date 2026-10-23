import { zxcvbn, zxcvbnOptions, type ZxcvbnResult } from "@zxcvbn-ts/core";
import * as common from "@zxcvbn-ts/language-common";

// All dictionaries ship in the bundle: no network request is ever made.
zxcvbnOptions.setOptions({
  graphs: common.adjacencyGraphs,
  dictionary: {
    ...common.dictionary,
    userInputs: ["vaultly"],
  },
});

export interface Strength {
  score: 0 | 1 | 2 | 3 | 4;
  label: string;
  warning: string | null;
  suggestions: string[];
  guessesLog10: number;
}

const LABELS = ["Very weak", "Weak", "Fair", "Strong", "Excellent"] as const;

export function measure(password: string): Strength {
  const result: ZxcvbnResult = zxcvbn(password);
  const score = result.score as Strength["score"];
  return {
    score,
    label: LABELS[score] ?? "Very weak",
    warning: result.feedback.warning ?? null,
    suggestions: result.feedback.suggestions ?? [],
    guessesLog10: result.guessesLog10,
  };
}

/** Minimum the backend enforces as well; the UI refuses earlier. */
export const MIN_MASTER_PASSWORD_LENGTH = 12;
