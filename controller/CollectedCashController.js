const CollectedCash = require('../models/CollectedCash');

exports.createCollectedCash = async (req, res, next) => {
    try {
        const { solutionCardId, name, amount } = req.body;
        const user = req.user.userId;

        if (!solutionCardId || !name || !amount) {
            return res.status(400).json({ message: 'solutionCardId, name and amount are required.' });
        }

        const collectedCash = await CollectedCash.create({
            solutionCardId,
            name,
            amount,
            user,
        });

        res.status(201).json({ message: 'Collected cash added.', collectedCash });
    } catch (error) {
        next(error);
    }
};

exports.getCollectedCashBySolution = async (req, res, next) => {
    try {
        const { solutionCardId } = req.params;
        const collectedCash = await CollectedCash.find({ solutionCardId })
            .sort({ collectedDate: -1 });
        res.json({ collectedCash });
    } catch (error) {
        next(error);
    }
};

exports.updateCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const { name, amount } = req.body;
        const user = req.user.userId;

        const updated = await CollectedCash.findByIdAndUpdate(
            id,
            { name, amount, user },
            { new: true }
        );

        if (!updated) return res.status(404).json({ message: 'Collected cash entry not found.' });

        res.json({ message: 'Collected cash updated.', collectedCash: updated });
    } catch (error) {
        next(error);
    }
};

exports.deleteCollectedCash = async (req, res, next) => {
    try {
        const { id } = req.params;
        const deleted = await CollectedCash.findByIdAndDelete(id);

        if (!deleted) return res.status(404).json({ message: 'Collected cash entry not found.' });

        res.json({ message: 'Collected cash entry deleted.' });
    } catch (error) {
        next(error);
    }
};
