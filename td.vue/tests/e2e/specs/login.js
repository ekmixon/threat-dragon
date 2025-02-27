describe('login', () => {
    beforeEach(() => {
        cy.setupTest();
    });

    describe('local login', () => {
        it('logs in using the local storage option', () => {
            cy.get('#local-login-btn').click();
            cy.contains('Logged in as Guest');
            cy.url().should('contain', '/dashboard');
        });
    });
});
