"""Real small CPU tensor gradients, not pretrained-model or quality evidence."""
from types import SimpleNamespace
import json
import subprocess
import sys
import unittest
from unittest.mock import patch

import torch

import llm_answer_eos_research_v3 as research
import llm_runtime_pilot as runtime


def tiny_training():
    class TinyModel(torch.nn.Module):
        def __init__(self):
            super().__init__()
            self.table = torch.nn.Parameter(torch.zeros(3, 3))
            self.forward_shapes = []

        def forward(self, input_ids, attention_mask, use_cache):
            self.forward_shapes.append(tuple(input_ids.shape))
            return SimpleNamespace(logits=self.table[input_ids])

    torch.set_num_threads(1)
    model = TinyModel()
    tokenizer = SimpleNamespace(eos_token_id=2, encode=lambda text, add_special_tokens: [1])
    plan = dict(training_steps=10, seed=7, tasks=runtime.tasks(), input_tokens_max=128, backend='cpu')
    # Explicit synthetic prompt lengths only; no public tokenizer claim.
    prompts = [[0] * n for n in [48] * 9 + [54]]
    with patch.object(runtime, 'prompt_tokens', side_effect=prompts):
        observed = research.train(model, tokenizer, plan, torch, torch.device('cpu'))
    return dict(training=observed, forward_shapes=model.forward_shapes,
                parameters_changed=bool((model.table.detach() != 0).any()))


class AnswerEosLossTests(unittest.TestCase):
    def setUp(self):
        torch.set_num_threads(1)
        self.logits = torch.arange(24, dtype=torch.float64).reshape(1, 6, 4).remainder(7).requires_grad_()
        self.labels = torch.tensor([[-100, -100, 1, 2, 2, 2]])

    def test_exact_answer_half_and_all_three_eos_share_half(self):
        individual = torch.nn.functional.cross_entropy(self.logits[0, 1:5], self.labels[0, 2:], reduction='none')
        expected = individual[0] / 2 + individual[1:].sum() / 6
        actual = research.weighted_loss(self.logits, self.labels, 2, torch)
        self.assertTrue(torch.allclose(actual, expected, atol=1e-14, rtol=0))
        self.assertNotEqual(float(actual.detach()), float(individual.mean().detach()))

    def test_every_supervised_token_has_gradient_and_masked_positions_do_not(self):
        research.weighted_loss(self.logits, self.labels, 2, torch).backward()
        counts = self.logits.grad.abs().sum(dim=-1)[0]
        self.assertTrue(bool((counts[1:5] > 0).all()))
        self.assertEqual(float(counts[0]), 0)
        self.assertEqual(float(counts[5]), 0)

    def test_prompt_mask_and_single_eos_shortcut_are_rejected(self):
        labels = self.labels.clone(); labels[0, 0] = 1
        with self.assertRaisesRegex(ValueError, 'LOSS_SHAPE'):
            research.weighted_loss(self.logits, labels, 2, torch)
        with self.assertRaisesRegex(ValueError, 'LOSS_SHAPE'):
            research.weighted_loss(self.logits[:, :4], self.labels[:, :4], 2, torch)

    def test_ignored_prompt_logit_does_not_change_objective(self):
        changed = self.logits.detach().clone()
        changed[:, 0] = torch.tensor([1000, -1000, 0, 0])
        self.assertEqual(float(research.weighted_loss(changed, self.labels, 2, torch)),
                         float(research.weighted_loss(self.logits, self.labels, 2, torch).detach()))

    def test_tiny_actual_training_measures_ten_forwards_and_forty_live_targets(self):
        # Keep native profiler diagnostics separate from unittest's partial
        # result line. A failed worker retains both streams in the assertion.
        result = subprocess.run([sys.executable, '-B', __file__, '--tiny-worker'],
                                capture_output=True, text=True, timeout=60)
        self.assertEqual(result.returncode, 0, result.stdout + result.stderr)
        actual = json.loads(result.stdout)
        observed = actual['training']
        self.assertEqual(actual['forward_shapes'], [[1, 52]] * 9 + [[1, 58]])
        self.assertEqual((observed['steps'], observed['tokens'], observed['supervised_tokens']), (10, 526, 40))
        self.assertEqual(observed['objective']['nonzero_weight_tokens'], 40)
        self.assertTrue(actual['parameters_changed'])
        self.assertEqual(len(observed['loss']), 10)


if __name__ == '__main__':
    if sys.argv[1:] == ['--tiny-worker']:
        print(json.dumps(tiny_training(), sort_keys=True))
    else:
        unittest.main(verbosity=2)
