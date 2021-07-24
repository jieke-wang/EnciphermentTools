using EnciphermentTools.Encipherment.Service;
using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Data;
using System.Drawing;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows.Forms;

namespace EnciphermentTools
{
    public partial class Form1 : Form
    {
        public Form1()
        {
            InitializeComponent();
        }

        private void btnGenerate_Click(object sender, EventArgs e)
        {
            Pbkdf2HelperService service = new Pbkdf2HelperService();
            string input = txtInput.Text.Trim();
            string hash = service.CreateHash(input);
            txtOutput.Text = hash;
        }
    }
}
