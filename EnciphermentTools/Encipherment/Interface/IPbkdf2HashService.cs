using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace EnciphermentTools.Encipherment.Interface
{
    public interface IPbkdf2HashService
    {
        Byte[] GetBytes(int count);
    }
}
